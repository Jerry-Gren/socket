// clang-format off
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#define SERVER_PORT 4468
#define MAX_CLIENT_QUEUE 20

#include "include/file_transfer.h"
#include "include/glog_wrapper.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/shell_exec.h"
// clang-format on

namespace fs = std::filesystem;

std::atomic<bool> g_server_running(true);

struct ShellInputKey {
	uint64_t connection_id = 0;
	uint64_t request_id = 0;

	bool operator<(const ShellInputKey &other) const
	{
		if (connection_id != other.connection_id) {
			return connection_id < other.connection_id;
		}
		return request_id < other.request_id;
	}
};

struct ShellInputQueue {
	std::mutex mutex;
	std::condition_variable cv;
	std::deque<ShellInputChunk> chunks;
	bool closed = false;
};

std::mutex g_shell_input_mutex;
std::map<ShellInputKey, std::shared_ptr<ShellInputQueue>> g_shell_inputs;

void signal_handler(int signum)
{
	LOG(INFO) << "[Info] Signal " << signum << " received. Shutting down...";
	g_server_running = false;
}

std::shared_ptr<ShellInputQueue> register_shell_input_queue(
    const ShellInputKey &key)
{
	auto queue = std::make_shared<ShellInputQueue>();
	std::lock_guard<std::mutex> lock(g_shell_input_mutex);
	g_shell_inputs[key] = queue;
	return queue;
}

void unregister_shell_input_queue(const ShellInputKey &key)
{
	std::shared_ptr<ShellInputQueue> queue;
	{
		std::lock_guard<std::mutex> lock(g_shell_input_mutex);
		auto it = g_shell_inputs.find(key);
		if (it == g_shell_inputs.end()) {
			return;
		}
		queue = it->second;
		g_shell_inputs.erase(it);
	}
	{
		std::lock_guard<std::mutex> lock(queue->mutex);
		queue->closed = true;
	}
	queue->cv.notify_all();
}

bool push_shell_input(const ShellInputKey &key,
                      const ShellExecStdinPayload &payload)
{
	std::shared_ptr<ShellInputQueue> queue;
	{
		std::lock_guard<std::mutex> lock(g_shell_input_mutex);
		auto it = g_shell_inputs.find(key);
		if (it == g_shell_inputs.end()) {
			return false;
		}
		queue = it->second;
	}

	{
		std::lock_guard<std::mutex> lock(queue->mutex);
		if (queue->closed) {
			return false;
		}
		queue->chunks.push_back(ShellInputChunk{payload.eof, payload.data});
		if (payload.eof) {
			queue->closed = true;
		}
	}
	queue->cv.notify_one();
	return true;
}

bool pop_shell_input(const std::shared_ptr<ShellInputQueue> &queue,
                     ShellInputChunk &chunk,
                     std::chrono::milliseconds max_wait)
{
	std::unique_lock<std::mutex> lock(queue->mutex);
	if (queue->chunks.empty() && !queue->closed && max_wait.count() > 0) {
		queue->cv.wait_for(lock, max_wait);
	}
	if (queue->chunks.empty()) {
		if (queue->closed) {
			chunk.eof = true;
			chunk.data.clear();
			return true;
		}
		return false;
	}
	chunk = std::move(queue->chunks.front());
	queue->chunks.pop_front();
	return true;
}

bool send_packet_locked(int socket, SecureSession &secure_session,
                        std::mutex &send_mutex, const Packet &pkt)
{
	std::lock_guard<std::mutex> lock(send_mutex);
	return send_secure_packet(socket, secure_session, pkt);
}

void send_file_result(int socket, SecureSession &secure_session,
                      std::mutex &send_mutex, uint64_t request_id,
                      bool success, int32_t code,
                      const std::string &message)
{
	Packet pkt;
	pkt.type = MessageType::FILE_RESULT;
	pkt.content =
	    create_file_result_payload(request_id, success, code, message);
	send_packet_locked(socket, secure_session, send_mutex, pkt);
}

void run_shell_exec(int socket, SecureSession *secure_session,
                    std::mutex *send_mutex, uint64_t connection_id,
                    ShellExecRequestPayload request,
                    std::shared_ptr<ShellInputQueue> input_queue)
{
	ShellInputKey input_key{connection_id, request.request_id};

	auto on_output = [&](ShellOutputStream stream, const std::string &data) {
		if (!g_server_running || data.empty()) {
			return;
		}
		Packet pkt;
		pkt.type = MessageType::SHELL_EXEC_OUTPUT;
		pkt.content = create_shell_exec_output_payload(
		    0, request.request_id, stream, data);
		send_packet_locked(socket, *secure_session, *send_mutex, pkt);
	};

	auto on_input = [&](ShellInputChunk &chunk,
	                    std::chrono::milliseconds max_wait) {
		return pop_shell_input(input_queue, chunk, max_wait);
	};

	ShellExecResultPayload result =
	    execute_shell_command(request, on_output, on_input);
	unregister_shell_input_queue(input_key);

	Packet pkt;
	pkt.type = MessageType::SHELL_EXEC_RESULT;
	pkt.content = create_shell_exec_result_payload(
	    0, request.request_id, result.exit_code, result.timed_out,
	    result.message);
	send_packet_locked(socket, *secure_session, *send_mutex, pkt);
}

void handle_shell_exec_request(int socket, SecureSession &secure_session,
                               std::mutex &send_mutex, uint64_t connection_id,
                               const std::string &content)
{
	ShellExecRequestPayload request;
	if (!parse_shell_exec_request_payload(content, request)) {
		LOG(ERROR) << "[Shell] Invalid exec request";
		return;
	}

	auto input_queue = register_shell_input_queue(
	    ShellInputKey{connection_id, request.request_id});
	std::thread(run_shell_exec, socket, &secure_session, &send_mutex,
	            connection_id, request, input_queue)
	    .detach();
}

void handle_shell_stdin(uint64_t connection_id, const std::string &content)
{
	ShellExecStdinPayload input;
	if (!parse_shell_exec_stdin_payload(content, input)) {
		LOG(ERROR) << "[Shell] Invalid stdin payload";
		return;
	}
	push_shell_input(ShellInputKey{connection_id, input.request_id}, input);
}

bool is_safe_destination(const fs::path &path)
{
	for (const auto &part : path) {
		if (part == "..") {
			return false;
		}
	}
	return true;
}

void handle_file_put_request(std::map<uint64_t, std::ofstream> &uploads,
                             int socket, SecureSession &secure_session,
                             std::mutex &send_mutex,
                             const std::string &content)
{
	FileRequestPayload request;
	if (!parse_file_request_payload(content, request)) {
		LOG(ERROR) << "[File] Invalid put request";
		return;
	}

	fs::path path = fs::path(request.path);
	if (!is_safe_destination(path)) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 "refusing path containing '..'");
		return;
	}

	std::error_code ec;
	if (path.has_parent_path()) {
		fs::create_directories(path.parent_path(), ec);
		if (ec) {
			send_file_result(socket, secure_session, send_mutex,
			                 request.request_id, false, 1,
			                 "failed to create destination directory");
			return;
		}
	}

	auto &stream = uploads[request.request_id];
	stream.open(path, std::ios::binary | std::ios::trunc);
	if (!stream.is_open()) {
		uploads.erase(request.request_id);
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 "failed to open destination file");
	}
}

void handle_file_data(std::map<uint64_t, std::ofstream> &uploads,
                      int socket, SecureSession &secure_session,
                      std::mutex &send_mutex, const std::string &content)
{
	FileDataPayload data;
	if (!parse_file_data_payload(content, data)) {
		LOG(ERROR) << "[File] Invalid data payload";
		return;
	}

	auto it = uploads.find(data.request_id);
	if (it == uploads.end()) {
		send_file_result(socket, secure_session, send_mutex,
		                 data.request_id, false, 1,
		                 "upload request not found");
		return;
	}

	if (!data.data.empty()) {
		it->second.write(data.data.data(), data.data.size());
		if (!it->second.good()) {
			it->second.close();
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1,
			                 "failed while writing destination file");
			return;
		}
	}

	if (data.eof) {
		it->second.close();
		uploads.erase(it);
		send_file_result(socket, secure_session, send_mutex,
		                 data.request_id, true, 0, "completed");
	}
}

void handle_file_get_request(int socket, SecureSession &secure_session,
                             std::mutex &send_mutex,
                             const std::string &content)
{
	FileRequestPayload request;
	if (!parse_file_request_payload(content, request)) {
		LOG(ERROR) << "[File] Invalid get request";
		return;
	}

	fs::path path = fs::path(request.path);
	if (!fs::exists(path) || !fs::is_regular_file(path)) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 "remote file does not exist");
		return;
	}

	uint64_t total_size = fs::file_size(path);
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 "failed to open remote file");
		return;
	}

	size_t chunk_size = calculate_file_chunk_size(total_size);
	std::string buffer(chunk_size, '\0');
	uint64_t bytes_sent = 0;

	while (g_server_running &&
	       (file.read(buffer.data(), chunk_size) || file.gcount() > 0)) {
		size_t bytes_read = static_cast<size_t>(file.gcount());
		bytes_sent += bytes_read;

		Packet pkt;
		pkt.type = MessageType::FILE_DATA;
		pkt.content = create_file_data_payload(
		    request.request_id, total_size, bytes_sent, false,
		    std::string(buffer.data(), bytes_read));
		if (!send_packet_locked(socket, secure_session, send_mutex, pkt)) {
			return;
		}
	}

	Packet eof_pkt;
	eof_pkt.type = MessageType::FILE_DATA;
	eof_pkt.content = create_file_data_payload(
	    request.request_id, total_size, total_size, true, "");
	if (send_packet_locked(socket, secure_session, send_mutex, eof_pkt)) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, true, 0, "completed");
	}
}

void handle_connection(int socket, SecureSession secure_session,
                       uint64_t connection_id)
{
	std::mutex send_mutex;
	std::map<uint64_t, std::ofstream> uploads;

	while (g_server_running) {
		Packet pkt;
		if (!read_secure_packet(socket, secure_session, pkt)) {
			break;
		}

		switch (pkt.type) {
		case MessageType::SHELL_EXEC_REQUEST:
			handle_shell_exec_request(socket, secure_session, send_mutex,
			                          connection_id, pkt.content);
			break;
		case MessageType::SHELL_EXEC_STDIN:
			handle_shell_stdin(connection_id, pkt.content);
			break;
		case MessageType::FILE_PUT_REQUEST:
			handle_file_put_request(uploads, socket, secure_session,
			                        send_mutex, pkt.content);
			break;
		case MessageType::FILE_DATA:
			handle_file_data(uploads, socket, secure_session,
			                 send_mutex, pkt.content);
			break;
		case MessageType::FILE_GET_REQUEST:
			handle_file_get_request(socket, secure_session, send_mutex,
			                        pkt.content);
			break;
		case MessageType::DISCONNECT_REQUEST:
			return;
		default:
			LOG(WARNING) << "[Warning] Unsupported packet type: "
			             << MessageTypeToString(pkt.type);
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	int port = SERVER_PORT;
	if (argc == 3 && std::string(argv[1]) == "-p") {
		port = std::stoi(argv[2]);
	}

	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		LOG(ERROR) << "[Error] Failed to create socket";
		return 1;
	}

	int opt = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(port);

	if (bind(server_socket, (struct sockaddr *)&server_address,
	         sizeof(server_address)) < 0) {
		LOG(ERROR) << "[Error] Binding failed";
		close(server_socket);
		return 1;
	}

	if (listen(server_socket, MAX_CLIENT_QUEUE) < 0) {
		LOG(ERROR) << "[Error] Listening failed";
		close(server_socket);
		return 1;
	}

	LOG(INFO) << "[Info] Server is listening on port " << port << "...";
	std::atomic<uint64_t> next_connection_id(1);

	while (g_server_running) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(server_socket, &read_fds);

		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int activity = select(server_socket + 1, &read_fds, NULL, NULL, &tv);
		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "[Error] select() error";
			break;
		}
		if (activity <= 0 || !FD_ISSET(server_socket, &read_fds)) {
			continue;
		}

		struct sockaddr_in client_address;
		socklen_t client_address_length = sizeof(client_address);
		int client_socket =
		    accept(server_socket, (struct sockaddr *)&client_address,
		           &client_address_length);
		if (client_socket < 0) {
			LOG(ERROR) << "[Error] accept() failed: " << strerror(errno);
			continue;
		}

		SecureSession secure_session;
		if (!perform_server_handshake(client_socket, secure_session)) {
			LOG(ERROR) << "[Error] Secure handshake failed";
			close(client_socket);
			continue;
		}

		uint64_t connection_id = next_connection_id.fetch_add(1);
		std::thread([client_socket, secure_session, connection_id]() mutable {
			handle_connection(client_socket, secure_session, connection_id);
			shutdown(client_socket, SHUT_RDWR);
			close(client_socket);
		}).detach();
	}

	close(server_socket);
	LOG(INFO) << "[Info] Server has shut down.";
	return 0;
}
