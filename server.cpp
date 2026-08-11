// clang-format off
#include <iostream>
#include <string>
#include <cstring>         // For memset
#include <unistd.h>        // For close
#include <sys/socket.h>    // For socket functions
#include <netinet/in.h>    // For sockaddr_in
#include <thread>          // For threading
#include <mutex>           // For std::mutex
#include <csignal>         // For signal handling
#include <atomic>          // For std::atomic
#include <sys/select.h>    // For select()
#include <cerrno>          // For errno
#include <nlohmann/json.hpp>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>

#include <chrono>
#include <cmath>
#include <iomanip>
#include <sstream>

#define SERVER_PORT 4468
#define MAX_CLIENT_QUEUE 20

#include "include/glog_wrapper.h"
#include "include/file_transfer.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/shell_exec.h"
#include "include/client_info.h"
#include "include/client_manager.h"
#include "include/utility.h"

using json = nlohmann::json;
// clang-format on

std::atomic<bool> g_server_running(true);
ClientManager g_client_manager;
const std::string g_server_name = "Lab7-SocketServer";

struct TransferProgressState {
	int last_percent = -1;
	std::chrono::steady_clock::time_point started_at;
};

struct ShellInputKey {
	uint64_t peer_id = 0;
	uint64_t request_id = 0;

	bool operator<(const ShellInputKey &other) const
	{
		if (peer_id != other.peer_id) return peer_id < other.peer_id;
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

// Signal handler function
// Called when SIGINT (Ctrl+C) or SIGTERM (kill) is received
void signal_handler(int signum)
{
	LOG(INFO) << "[Info] Interrupt signal (" << signum
	          << ") received. Shutting down...";
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

std::string get_current_time_str()
{
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);

	std::tm timeinfo = *gmtime(&in_time_t);

	std::ostringstream oss;
	oss << std::put_time(&timeinfo, "%Y-%m-%dT%H:%M:%SZ");
	return oss.str();
}

std::string format_duration(std::chrono::seconds duration)
{
	uint64_t total_seconds = static_cast<uint64_t>(duration.count());
	uint64_t hours = total_seconds / 3600;
	uint64_t minutes = (total_seconds % 3600) / 60;
	uint64_t seconds = total_seconds % 60;

	std::ostringstream oss;
	oss << std::setfill('0') << std::setw(2) << hours << ":"
	    << std::setw(2) << minutes << ":" << std::setw(2) << seconds;
	return oss.str();
}

std::string estimate_remaining_time(
    uint64_t bytes_sent, uint64_t total_size,
    std::chrono::steady_clock::time_point started_at,
    std::chrono::steady_clock::time_point now)
{
	if (total_size == 0 || bytes_sent >= total_size) {
		return "00:00:00";
	}

	std::chrono::duration<long double> elapsed = now - started_at;
	if (bytes_sent == 0 || elapsed.count() <= 0.0L) {
		return "--:--:--";
	}

	long double bytes_per_second =
	    static_cast<long double>(bytes_sent) / elapsed.count();
	if (bytes_per_second <= 0.0L) {
		return "--:--:--";
	}

	long double remaining_seconds =
	    static_cast<long double>(total_size - bytes_sent) / bytes_per_second;
	return format_duration(std::chrono::seconds(
	    static_cast<int64_t>(std::ceil(remaining_seconds))));
}

void handle_get_time_request(int client_id)
{
	Packet time_response_pkt;
	time_response_pkt.type = MessageType::GET_TIME_RESPONSE;

	std::string time_str = get_current_time_str();
	time_response_pkt.content = json{{"time", time_str}}.dump();

	g_client_manager.send_to_client(client_id, time_response_pkt);
}

void handle_get_name_request(int client_id)
{
	Packet name_response_pkt;
	name_response_pkt.type = MessageType::GET_NAME_RESPONSE;

	name_response_pkt.content = json{{"name", g_server_name}}.dump();

	g_client_manager.send_to_client(client_id, name_response_pkt);
}

void handle_get_client_list_request(int client_id)
{
	Packet list_response_pkt;
	list_response_pkt.type = MessageType::GET_CLIENT_LIST_RESPONSE;

	json client_list_json = json::array();

	std::vector<ClientInfo> clients = g_client_manager.get_all_clients();

	for (const auto& client : clients) {
		client_list_json.push_back(json{
		    {"id", client.client_id},
		    {"ip", client.ip_address},
		    {"port", client.port}
		});
	}

	list_response_pkt.content = json{
	        {"clients", client_list_json}
	}.dump();

	g_client_manager.send_to_client(client_id, list_response_pkt);
}

void handle_send_message_request(int client_id, const std::string &content)
{
    uint64_t target_id;
    std::string message;
    Packet response_pkt;
    response_pkt.type = MessageType::SEND_MESSAGE_RESPONSE;

    try {
        json data = json::parse(content);
    	target_id = data.at("target_id").get<uint64_t>();
        message = data.at("message").get<std::string>();
    } catch (const json::exception& e) {
        LOG(ERROR) << "[Error] Failed to parse SEND_MESSAGE_REQUEST from client "
                   << client_id << ": " << e.what();
        response_pkt.content = json{
            {"status", "error"},
            {"message", "Bad request format"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
        return;
    }

    if (!g_client_manager.get_client(target_id).has_value()) {
        LOG(WARNING) << "[Warning] Client " << client_id << " tried to send to non-existent client ID "
                     << target_id;
        response_pkt.content = json{
            {"status", "error"},
            {"target_id", target_id},
            {"message", "Client not found"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
        return;
    }

    Packet forward_pkt;
    forward_pkt.type = MessageType::MESSAGE_INDICATION;
    forward_pkt.content = json{
        {"from_id", client_id},
        {"message", sanitize_for_terminal(message)}
    }.dump();

    if (g_client_manager.send_to_client(target_id, forward_pkt)) {
        response_pkt.content = json{
            {"status", "success"},
            {"target_id", target_id}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
    } else {
        response_pkt.content = json{
            {"status", "error"},
            {"target_id", target_id},
            {"message", "Failed to send message"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
    }
}

void handle_send_file_request(int client_id, const std::string &content)
{
	FileTransferPayload file_payload;
	if (!parse_file_transfer_payload(content, file_payload)) {
		LOG(ERROR) << "Failed to parse file request from " << client_id;
		return;
	}

	uint64_t target_id = file_payload.peer_id;
	if (!g_client_manager.get_client(target_id).has_value()) {
		return;
	}

	Packet forward_pkt;
	forward_pkt.type = MessageType::FILE_INDICATION;
	forward_pkt.content = create_file_transfer_payload(
	    client_id, file_payload.total_size, file_payload.bytes_sent,
	    file_payload.eof, file_payload.filename, file_payload.data);

	g_client_manager.send_to_client(target_id, forward_pkt);
}

void run_server_shell_exec_request(int client_id,
                                   ShellExecRequestPayload request,
                                   std::shared_ptr<ShellInputQueue> input_queue)
{
	ShellInputKey input_key{static_cast<uint64_t>(client_id),
	                       request.request_id};

	auto on_output = [&](ShellOutputStream stream, const std::string &data) {
		if (!g_server_running || data.empty()) {
			return;
		}
		Packet output_pkt;
		output_pkt.type = MessageType::SHELL_EXEC_OUTPUT;
		output_pkt.content = create_shell_exec_output_payload(
		    0, request.request_id, stream, data);
		g_client_manager.send_to_client(client_id, output_pkt);
	};

	auto on_input = [&](ShellInputChunk &chunk,
	                    std::chrono::milliseconds max_wait) {
		return pop_shell_input(input_queue, chunk, max_wait);
	};

	ShellExecResultPayload result =
	    execute_shell_command(request, on_output, on_input);
	unregister_shell_input_queue(input_key);

	Packet result_pkt;
	result_pkt.type = MessageType::SHELL_EXEC_RESULT;
	result_pkt.content = create_shell_exec_result_payload(
	    0, request.request_id, result.exit_code, result.timed_out,
	    result.message);
	g_client_manager.send_to_client(client_id, result_pkt);
}

void handle_shell_exec_request(int client_id, const std::string &content)
{
	ShellExecRequestPayload request;
	if (!parse_shell_exec_request_payload(content, request)) {
		LOG(ERROR) << "Failed to parse shell request from " << client_id;
		return;
	}

	uint64_t target_id = request.peer_id;
	if (target_id == 0) {
		auto input_queue = register_shell_input_queue(
		    ShellInputKey{static_cast<uint64_t>(client_id),
		                  request.request_id});
		std::thread(run_server_shell_exec_request, client_id, request,
		            input_queue)
		    .detach();
		return;
	}

	if (!g_client_manager.get_client(target_id).has_value()) {
		Packet result_pkt;
		result_pkt.type = MessageType::SHELL_EXEC_RESULT;
		result_pkt.content = create_shell_exec_result_payload(
		    target_id, request.request_id, 255, false,
		    "target client not found");
		g_client_manager.send_to_client(client_id, result_pkt);
		return;
	}

	Packet forward_pkt;
	forward_pkt.type = MessageType::SHELL_EXEC_REQUEST;
	forward_pkt.content = create_shell_exec_request_payload(
	    client_id, request.request_id, request.timeout_seconds,
	    request.command);
	g_client_manager.send_to_client(target_id, forward_pkt);
}

void handle_shell_exec_stdin(int client_id, const std::string &content)
{
	ShellExecStdinPayload input;
	if (!parse_shell_exec_stdin_payload(content, input)) {
		LOG(ERROR) << "Failed to parse shell stdin from " << client_id;
		return;
	}

	uint64_t target_id = input.peer_id;
	if (target_id == 0) {
		push_shell_input(
		    ShellInputKey{static_cast<uint64_t>(client_id), input.request_id},
		    input);
		return;
	}

	if (!g_client_manager.get_client(target_id).has_value()) {
		return;
	}

	Packet forward_pkt;
	forward_pkt.type = MessageType::SHELL_EXEC_STDIN;
	forward_pkt.content = create_shell_exec_stdin_payload(
	    client_id, input.request_id, input.eof, input.data);
	g_client_manager.send_to_client(target_id, forward_pkt);
}

void handle_shell_exec_output(int client_id, const std::string &content)
{
	ShellExecOutputPayload output;
	if (!parse_shell_exec_output_payload(content, output)) {
		LOG(ERROR) << "Failed to parse shell output from " << client_id;
		return;
	}

	uint64_t target_id = output.peer_id;
	if (!g_client_manager.get_client(target_id).has_value()) {
		return;
	}

	Packet forward_pkt;
	forward_pkt.type = MessageType::SHELL_EXEC_OUTPUT;
	forward_pkt.content = create_shell_exec_output_payload(
	    client_id, output.request_id, output.stream, output.data);
	g_client_manager.send_to_client(target_id, forward_pkt);
}

void handle_shell_exec_result(int client_id, const std::string &content)
{
	ShellExecResultPayload result;
	if (!parse_shell_exec_result_payload(content, result)) {
		LOG(ERROR) << "Failed to parse shell result from " << client_id;
		return;
	}

	uint64_t target_id = result.peer_id;
	if (!g_client_manager.get_client(target_id).has_value()) {
		return;
	}

	Packet forward_pkt;
	forward_pkt.type = MessageType::SHELL_EXEC_RESULT;
	forward_pkt.content = create_shell_exec_result_payload(
	    client_id, result.request_id, result.exit_code, result.timed_out,
	    result.message);
	g_client_manager.send_to_client(target_id, forward_pkt);
}

void log_received_packet(int client_id, const Packet &pkt)
{
	if (pkt.type == MessageType::SHELL_EXEC_REQUEST ||
	    pkt.type == MessageType::SHELL_EXEC_STDIN ||
	    pkt.type == MessageType::SHELL_EXEC_OUTPUT ||
	    pkt.type == MessageType::SHELL_EXEC_RESULT) {
		LOG(INFO) << "Received from ID " << client_id
		          << ", Type: " << MessageTypeToString(pkt.type);
		return;
	}

	if (pkt.type != MessageType::SEND_FILE_REQUEST) {
		LOG(INFO) << "Received from ID " << client_id
		          << ", Type: " << MessageTypeToString(pkt.type)
		          << ", Payload: " << sanitize_for_terminal(pkt.content);
		return;
	}

	FileTransferPayload file_payload;
	if (!parse_file_transfer_payload(pkt.content, file_payload)) {
		LOG(WARNING) << "[File Transfer] Failed to parse progress from client "
		             << client_id;
		return;
	}

	uint64_t total_size = file_payload.total_size;
	uint64_t bytes_sent = file_payload.bytes_sent;
	int progress_percent = 0;
	if (total_size > 0) {
		if (bytes_sent > total_size) {
			bytes_sent = total_size;
		}
		progress_percent = static_cast<int>(
		    (static_cast<long double>(bytes_sent) * 100.0L) /
		    static_cast<long double>(total_size));
	}
	if (file_payload.eof) {
		progress_percent = 100;
	}
	static std::map<std::string, TransferProgressState> progress_by_transfer;
	static std::mutex progress_log_mutex;
	std::string transfer_key = std::to_string(client_id) + ":" +
	                           std::to_string(file_payload.peer_id) + ":" +
	                           file_payload.filename;
	std::lock_guard<std::mutex> lock(progress_log_mutex);
	auto now = std::chrono::steady_clock::now();
	auto [progress_it, inserted] =
	    progress_by_transfer.try_emplace(transfer_key);
	if (inserted) {
		progress_it->second.started_at = now;
	}
	if (progress_percent == 0 && !file_payload.eof) {
		return;
	}

	if (progress_it->second.last_percent != progress_percent) {
		std::string eta = estimate_remaining_time(
		    bytes_sent, total_size, progress_it->second.started_at, now);
		std::cout << "\r\x1b[2K[File Transfer] "
		          << progress_percent << "% ETA " << eta << std::flush;
		progress_it->second.last_percent = progress_percent;
	}
	if (file_payload.eof) {
		std::cout << std::endl;
		progress_by_transfer.erase(transfer_key);
	}
}

void handle_unhandled_request(int client_id, MessageType type, const std::string &content)
{
	LOG(WARNING) << "[Warning] Unhandled message type from client " << client_id
	    << ": " << MessageTypeToString(type);

	Packet error_pkt;
	error_pkt.type = MessageType::SYSTEM_NOTICE_INDICATION;
	error_pkt.content = json{
	        {"notice", "Error: Unhandled or unknown command."}
	}.dump();
	g_client_manager.send_to_client(client_id, error_pkt);
}

// Client handler function
// This function is executed in a separate thread for each new connection
void handle_client(int client_id, int client_socket,
                   SecureSession secure_session)
{

	LOG(INFO) << "[Info] Client Handler started for ID: " << client_id
	          << ", Socket: " << client_socket;

	// Send an initial greeting message
	Packet greeting_pkt;
	greeting_pkt.type = MessageType::SYSTEM_NOTICE_INDICATION;
	greeting_pkt.content =
	    json{{"notice", "Hello! Your ID is " + std::to_string(client_id)}}
	        .dump();

	g_client_manager.send_to_client(client_id, greeting_pkt);

	bool client_requested_disconnect = false;

	// Main loop to handle incoming packets
	while (g_server_running && !client_requested_disconnect) {
		Packet received_pkt;
		if (!read_secure_packet(client_socket, secure_session, received_pkt)) {
			// read_secure_packet returns false on disconnect or critical error
			LOG(INFO) << "[Info] Client " << client_id
			          << " connection closed or errored.";
			break;
		}
		log_received_packet(client_id, received_pkt);

		switch (received_pkt.type) {
		case MessageType::GET_TIME_REQUEST:
			handle_get_time_request(client_id);
			break;
		case MessageType::GET_NAME_REQUEST:
			handle_get_name_request(client_id);
			break;
		case MessageType::GET_CLIENT_LIST_REQUEST:
			handle_get_client_list_request(client_id);
			break;
		case MessageType::SEND_MESSAGE_REQUEST:
			handle_send_message_request(client_id, received_pkt.content);
			break;
		case MessageType::SEND_FILE_REQUEST:
			handle_send_file_request(client_id, received_pkt.content);
			break;
		case MessageType::SHELL_EXEC_REQUEST:
			handle_shell_exec_request(client_id, received_pkt.content);
			break;
		case MessageType::SHELL_EXEC_STDIN:
			handle_shell_exec_stdin(client_id, received_pkt.content);
			break;
		case MessageType::SHELL_EXEC_OUTPUT:
			handle_shell_exec_output(client_id, received_pkt.content);
			break;
		case MessageType::SHELL_EXEC_RESULT:
			handle_shell_exec_result(client_id, received_pkt.content);
			break;
		case MessageType::DISCONNECT_REQUEST:
			LOG(INFO)
			    << "[Info] Client " << client_id << " requested disconnect.";
			client_requested_disconnect = true;
			break;
		default:
			handle_unhandled_request(client_id, received_pkt.type,
			                         received_pkt.content);
			break;
		}
	}

	LOG(INFO) << "[Info] Finished handling client ID: " << client_id;
	g_client_manager.remove_client(client_id);
}

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

	// Register signal handlers
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	int server_socket, client_socket;
	struct sockaddr_in server_address, client_address;
	socklen_t client_address_length = sizeof(client_address);

	// 1. Create socket
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		LOG(ERROR) << "[Error] Failed to create socket";
		return -1;
	}

	// Set socket option SO_REUSEADDR to allow reusing the port immediately
	// after server restarts
	int opt = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	// 2. Set server address
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(SERVER_PORT);

	// 3. Bind socket to local address
	if (bind(server_socket, (struct sockaddr *)&server_address,
	         sizeof(server_address)) < 0) {
		LOG(ERROR) << "[Error] Binding failed";
		return -1;
	}

	// 4. Listen to connection from client
	if (listen(server_socket, MAX_CLIENT_QUEUE) < 0) {
		LOG(ERROR) << "[Error] Listening failed";
		return -1;
	}
	LOG(INFO) << "[Info] Server is listening on port " << SERVER_PORT << "...";

	// Server main loop
	while (g_server_running) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(server_socket, &read_fds);

		// Set a timeout for select()
		struct timeval tv;
		tv.tv_sec = 1; // 1 second timeout
		tv.tv_usec = 0;

		// 5. Use select() for I/O multiplexing to wait for events
		// without blocking
		int activity = select(server_socket + 1, &read_fds, NULL, NULL, &tv);

		// If select() returns an error, but it's not an interrupt from
		// a signal (EINTR), then exit
		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "[Error] select() error";
			break;
		}

		// A new connection is pending
		if (activity > 0 && FD_ISSET(server_socket, &read_fds)) {
			// 6. Accept the new connection
			client_socket =
			    accept(server_socket, (struct sockaddr *)&client_address,
			           &client_address_length);

			if (client_socket < 0) {
				LOG(ERROR)
				    << "[Error] accept() failed: " << strerror(errno);
			} else {
				// Get client details for logging and ClientManager
				std::string ip = inet_ntoa(client_address.sin_addr);
				int port = ntohs(client_address.sin_port);

				SecureSession secure_session;
				if (!perform_server_handshake(client_socket, secure_session)) {
					LOG(ERROR) << "[Error] Secure handshake failed for "
					           << ip << ":" << port;
					close(client_socket);
					continue;
				}

				// 7. Add client to manager and get its ID
				int client_id =
				    g_client_manager.add_client(client_socket, ip, port,
				                                secure_session);

				// 8. Create and detach a new thread to handle the client
				// request.
				std::thread(handle_client, client_id, client_socket,
				            secure_session)
				    .detach();
			}
		}
	}

	// Close socket
	LOG(INFO) << "[Info] Server is shutting down. Closing server socket to stop new connections.";
	close(server_socket);

	// Prepare shutdown indication packet
	LOG(INFO) << "[Info] Notifying all connected clients of shutdown...";
	Packet shutdown_pkt;
	shutdown_pkt.type = MessageType::SERVER_SHUTDOWN_INDICATION;
	shutdown_pkt.content = json{
	        {"notice", "Server is shutting down for maintenance. Please reconnect later."}
	}.dump();

	// Notify all clients
	std::vector<ClientInfo> all_clients = g_client_manager.get_all_clients();
	for (const auto& client : all_clients) {
		LOG(INFO) << "[Info] Sending shutdown notice to Client ID: " << client.client_id;
		g_client_manager.send_to_client(client.client_id, shutdown_pkt);
		g_client_manager.remove_client(client.client_id);
	}

	LOG(INFO) << "[Info] All clients notified. Server has shut down.";

	return 0;
}
