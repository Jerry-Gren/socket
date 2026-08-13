// clang-format off
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define SERVER_PORT 4468
#define MAX_CLIENT_QUEUE 20

#include "include/file_transfer.h"
#include "include/glog_wrapper.h"
#include "include/auth_protocol.h"
#include "include/identity.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/shell_exec.h"
#include "include/utility.h"
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

struct ServerOptions {
	int port = SERVER_PORT;
	std::string host_key_path;
	std::string authorized_keys_path;
};

struct AuthenticatedUser {
	std::string username;
	uid_t uid = 0;
	gid_t gid = 0;
	std::string home;
};

struct TransferEntry {
	fs::path path;
	std::string relative_path;
	FileEntryType type = FileEntryType::REGULAR_FILE;
	uint32_t mode = 0644;
	uint64_t size = 0;
};

struct UploadState {
	fs::path base_path;
	bool recursive = false;
	std::ofstream stream;
	fs::path open_path;
	uint32_t open_mode = 0644;
	std::vector<std::pair<fs::path, uint32_t>> directories;
};

void signal_handler(int signum)
{
	LOG(INFO) << "[Info] Signal " << signum << " received. Shutting down...";
	g_server_running = false;
}

void print_usage(const char *program)
{
	std::cerr
	    << "Usage:\n"
	    << "  " << program << " [options]\n"
	    << "\n"
	    << "Options:\n"
	    << "  -p PORT                 Listen port (default 4468)\n"
	    << "  --host-key FILE         xshd Ed25519 host key\n"
	    << "  --authorized-keys FILE  Authorized user public keys\n"
	    << "  -h, --help              Show this help\n";
}

bool parse_port(const std::string &value, int &port)
{
	if (value.empty()) {
		return false;
	}
	for (unsigned char ch : value) {
		if (!std::isdigit(ch)) {
			return false;
		}
	}
	try {
		int parsed = std::stoi(value);
		if (parsed < 1 || parsed > 65535) {
			return false;
		}
		port = parsed;
		return true;
	} catch (...) {
		return false;
	}
}

bool parse_arguments(int argc, char *argv[], ServerOptions &options,
                     bool &show_help)
{
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help") {
			show_help = true;
			return true;
		}
		if (arg == "-p" || arg == "--host-key" ||
		    arg == "--authorized-keys") {
			if (++i >= argc) {
				std::cerr << "xshd: " << arg << " requires an argument\n";
				return false;
			}
			if (arg == "-p") {
				if (!parse_port(argv[i], options.port)) {
					std::cerr << "xshd: invalid port\n";
					return false;
				}
			} else if (arg == "--host-key") {
				options.host_key_path = argv[i];
			} else {
				options.authorized_keys_path = argv[i];
			}
			continue;
		}
		std::cerr << "xshd: unsupported option: " << arg << "\n";
		return false;
	}
	return true;
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

void send_auth_result(int socket, SecureSession &secure_session,
                      std::mutex &send_mutex, bool success,
                      const std::string &message)
{
	Packet pkt;
	pkt.type = MessageType::AUTH_RESULT;
	pkt.content = create_auth_result_payload(success, message);
	send_packet_locked(socket, secure_session, send_mutex, pkt);
}

bool resolve_os_user(const std::string &username, AuthenticatedUser &user,
                     std::string &error)
{
	if (username.empty()) {
		error = "empty username";
		return false;
	}

	struct passwd pwd;
	struct passwd *result = nullptr;
	long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buffer_size < 1024) {
		buffer_size = 16384;
	}
	std::vector<char> buffer(static_cast<size_t>(buffer_size));
	int rc = getpwnam_r(username.c_str(), &pwd, buffer.data(),
	                    buffer.size(), &result);
	if (rc != 0 || result == nullptr) {
		error = "unknown OS user: " + username;
		return false;
	}

	user.username = username;
	user.uid = pwd.pw_uid;
	user.gid = pwd.pw_gid;
	user.home = pwd.pw_dir == nullptr ? "" : pwd.pw_dir;
	return true;
}

bool drop_to_user(const AuthenticatedUser &user, std::string &error)
{
	if (geteuid() == user.uid) {
		if (!user.home.empty()) {
			setenv("HOME", user.home.c_str(), 1);
		}
		setenv("USER", user.username.c_str(), 1);
		setenv("LOGNAME", user.username.c_str(), 1);
		return true;
	}
	if (geteuid() != 0) {
		error = "xshd is not running as root and cannot switch to user " +
		        user.username;
		return false;
	}

	if (initgroups(user.username.c_str(), user.gid) != 0) {
		error = "initgroups failed for " + user.username + ": " +
		        strerror(errno);
		return false;
	}
	if (setgid(user.gid) != 0) {
		error = "setgid failed for " + user.username + ": " +
		        strerror(errno);
		return false;
	}
	if (setuid(user.uid) != 0) {
		error = "setuid failed for " + user.username + ": " +
		        strerror(errno);
		return false;
	}
	if (setuid(0) == 0) {
		error = "failed to permanently drop root privileges";
		return false;
	}
	if (!user.home.empty()) {
		setenv("HOME", user.home.c_str(), 1);
	}
	setenv("USER", user.username.c_str(), 1);
	setenv("LOGNAME", user.username.c_str(), 1);
	return true;
}

bool authenticate_connection(int socket, SecureSession &secure_session,
                             std::mutex &send_mutex,
                             const std::string &authorized_keys_path,
                             AuthenticatedUser &user)
{
	Packet pkt;
	if (!read_secure_packet(socket, secure_session, pkt) ||
	    pkt.type != MessageType::AUTH_REQUEST) {
		send_auth_result(socket, secure_session, send_mutex, false,
		                 "authentication required");
		return false;
	}

	AuthRequestPayload request;
	if (!parse_auth_request_payload(pkt.content, request)) {
		send_auth_result(socket, secure_session, send_mutex, false,
		                 "invalid authentication request");
		return false;
	}

	std::string message = create_user_auth_message(
	    secure_session.session_id, request.username, request.public_key);
	if (!verify_ed25519(request.public_key, message, request.signature)) {
		send_auth_result(socket, secure_session, send_mutex, false,
		                 "invalid signature");
		return false;
	}

	std::string error;
	if (!is_authorized_user_key(authorized_keys_path, request.username,
	                            request.public_key, error)) {
		send_auth_result(socket, secure_session, send_mutex, false, error);
		return false;
	}

	if (!resolve_os_user(request.username, user, error)) {
		send_auth_result(socket, secure_session, send_mutex, false, error);
		return false;
	}
	if (!drop_to_user(user, error)) {
		send_auth_result(socket, secure_session, send_mutex, false, error);
		return false;
	}

	send_auth_result(socket, secure_session, send_mutex, true, "accepted");
	LOG(INFO) << "[Auth] Accepted user " << request.username
	          << " uid=" << user.uid;
	return true;
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

fs::path expand_remote_path(const std::string &path)
{
	if (path == "~" || path.rfind("~/", 0) == 0) {
		if (const char *home = std::getenv("HOME")) {
			if (*home != '\0') {
				fs::path expanded(home);
				if (path.size() > 2) {
					expanded /= path.substr(2);
				}
				return expanded;
			}
		}
	}
	return fs::path(path);
}

bool is_safe_relative_path(const std::string &relative_path)
{
	if (relative_path.empty()) {
		return true;
	}
	fs::path path(relative_path);
	if (path.is_absolute()) {
		return false;
	}
	for (const auto &part : path) {
		if (part == "..") {
			return false;
		}
	}
	return true;
}

fs::path target_for_entry(const fs::path &base_path,
                          const std::string &relative_path)
{
	if (relative_path.empty()) {
		return base_path;
	}
	return base_path / fs::path(relative_path);
}

bool chmod_path(const fs::path &path, uint32_t mode, std::string &error)
{
	std::error_code ec;
	fs::permissions(path, static_cast<fs::perms>(mode & 07777),
	                fs::perm_options::replace, ec);
	if (ec) {
		error = "failed to set permissions on " + path.string() + ": " +
		        ec.message();
		return false;
	}
	return true;
}

bool close_open_upload_file(UploadState &state, std::string &error)
{
	if (!state.stream.is_open()) {
		return true;
	}
	state.stream.close();
	if (!state.stream.good()) {
		error = "failed to close destination file";
		return false;
	}
	return chmod_path(state.open_path, state.open_mode, error);
}

bool apply_directory_modes(
    const std::vector<std::pair<fs::path, uint32_t>> &directories,
    std::string &error)
{
	for (auto it = directories.rbegin(); it != directories.rend(); ++it) {
		if (!chmod_path(it->first, it->second, error)) {
			return false;
		}
	}
	return true;
}

bool create_directory_at_path(const fs::path &path, std::string &error)
{
	std::error_code ec;
	if (fs::exists(path, ec)) {
		if (fs::is_directory(path, ec)) {
			return true;
		}
		error = "destination exists and is not a directory: " +
		        path.string();
		return false;
	}
	if (!path.parent_path().empty() && !fs::exists(path.parent_path(), ec)) {
		error = "destination parent does not exist: " +
		        path.parent_path().string();
		return false;
	}
	if (!path.parent_path().empty() &&
	    !fs::is_directory(path.parent_path(), ec)) {
		error = "destination parent is not a directory: " +
		        path.parent_path().string();
		return false;
	}
	if (!fs::create_directory(path, ec)) {
		error = "failed to create directory " + path.string() + ": " +
		        ec.message();
		return false;
	}
	return true;
}

bool validate_upload_destination(const fs::path &path, bool recursive,
                                 std::string &error)
{
	std::error_code ec;
	if (fs::exists(path, ec)) {
		if (!recursive && fs::is_directory(path, ec)) {
			error = "destination is a directory";
			return false;
		}
		if (recursive && !fs::is_directory(path, ec)) {
			error = "destination exists and is not a directory: " +
			        path.string();
			return false;
		}
		return true;
	}

	fs::path parent = path.parent_path();
	if (!parent.empty() && !fs::exists(parent, ec)) {
		error = "destination parent does not exist: " + parent.string();
		return false;
	}
	if (!parent.empty() && !fs::is_directory(parent, ec)) {
		error = "destination parent is not a directory: " +
		        parent.string();
		return false;
	}
	return true;
}

uint32_t file_mode(const fs::path &path, std::string &error)
{
	std::error_code ec;
	fs::perms perms = fs::status(path, ec).permissions();
	if (ec) {
		error = "failed to read permissions for " + path.string() +
		        ": " + ec.message();
		return 0;
	}
	return static_cast<uint32_t>(perms) & 07777;
}

bool append_transfer_entry(const fs::path &path,
                           const std::string &relative_path,
                           std::vector<TransferEntry> &entries,
                           uint64_t &total_size, std::string &error)
{
	std::error_code ec;
	fs::file_status status = fs::status(path, ec);
	if (ec) {
		error = "failed to stat " + path.string() + ": " + ec.message();
		return false;
	}

	TransferEntry entry;
	entry.path = path;
	entry.relative_path = relative_path;
	entry.mode = file_mode(path, error);
	if (!error.empty()) {
		return false;
	}
	if (fs::is_directory(status)) {
		entry.type = FileEntryType::DIRECTORY;
		entries.push_back(std::move(entry));
		return true;
	}
	if (!fs::is_regular_file(status)) {
		error = "unsupported file type: " + path.string();
		return false;
	}

	entry.type = FileEntryType::REGULAR_FILE;
	entry.size = fs::file_size(path, ec);
	if (ec) {
		error = "failed to read size for " + path.string() + ": " +
		        ec.message();
		return false;
	}
	total_size += entry.size;
	entries.push_back(std::move(entry));
	return true;
}

bool collect_transfer_entries(const fs::path &source, bool recursive,
                              std::vector<TransferEntry> &entries,
                              uint64_t &total_size, std::string &error)
{
	std::error_code ec;
	if (!fs::exists(source, ec)) {
		error = "remote path does not exist";
		return false;
	}
	if (fs::is_regular_file(source, ec)) {
		return append_transfer_entry(source, "", entries, total_size, error);
	}
	if (!fs::is_directory(source, ec)) {
		error = "remote path is not a regular file or directory";
		return false;
	}
	if (!recursive) {
		error = "remote path is a directory (use -r)";
		return false;
	}

	if (!append_transfer_entry(source, "", entries, total_size, error)) {
		return false;
	}
	fs::recursive_directory_iterator it(source, ec);
	fs::recursive_directory_iterator end;
	if (ec) {
		error = "failed to read directory " + source.string() + ": " +
		        ec.message();
		return false;
	}
	for (; it != end; it.increment(ec)) {
		if (ec) {
			error = "failed while reading directory " + source.string() +
			        ": " + ec.message();
			return false;
		}
		fs::path relative = fs::relative(it->path(), source, ec);
		if (ec) {
			error = "failed to build relative path for " +
			        it->path().string() + ": " + ec.message();
			return false;
		}
		if (!append_transfer_entry(it->path(), relative.generic_string(),
		                           entries, total_size, error)) {
			return false;
		}
	}
	return true;
}

bool send_file_entry(int socket, SecureSession &secure_session,
                     std::mutex &send_mutex, uint64_t request_id,
                     const TransferEntry &entry, uint64_t total_size,
                     uint64_t &bytes_sent, bool last_entry)
{
	if (entry.type == FileEntryType::DIRECTORY || entry.size == 0) {
		Packet pkt;
		pkt.type = MessageType::FILE_DATA;
		pkt.content = create_file_data_payload(
		    request_id, total_size, bytes_sent, entry.type, entry.mode,
		    entry.relative_path, last_entry, "");
		return send_packet_locked(socket, secure_session, send_mutex, pkt);
	}

	std::ifstream file(entry.path, std::ios::binary);
	if (!file.is_open()) {
		return false;
	}
	size_t chunk_size = calculate_file_chunk_size(total_size);
	std::string buffer(chunk_size, '\0');
	while (g_server_running &&
	       (file.read(buffer.data(), chunk_size) || file.gcount() > 0)) {
		size_t bytes_read = static_cast<size_t>(file.gcount());
		bytes_sent += bytes_read;
		bool eof = last_entry && bytes_sent >= total_size;

		Packet pkt;
		pkt.type = MessageType::FILE_DATA;
		pkt.content = create_file_data_payload(
		    request_id, total_size, bytes_sent, entry.type, entry.mode,
		    entry.relative_path, eof,
		    std::string(buffer.data(), bytes_read));
		if (!send_packet_locked(socket, secure_session, send_mutex, pkt)) {
			return false;
		}
	}
	return true;
}

void handle_file_put_request(std::map<uint64_t, UploadState> &uploads,
                             int socket, SecureSession &secure_session,
                             std::mutex &send_mutex,
                             const std::string &content)
{
	FileRequestPayload request;
	if (!parse_file_request_payload(content, request)) {
		LOG(ERROR) << "[File] Invalid put request";
		return;
	}

	fs::path path = expand_remote_path(request.path);

	std::string error;
	if (!validate_upload_destination(path, request.recursive, error)) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 error);
		return;
	}

	UploadState state;
	state.base_path = path;
	state.recursive = request.recursive;
	uploads[request.request_id] = std::move(state);
	send_file_result(socket, secure_session, send_mutex,
	                 request.request_id, true, 0, "ready");
}

void handle_file_data(std::map<uint64_t, UploadState> &uploads,
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

	if (!is_safe_relative_path(data.relative_path)) {
		send_file_result(socket, secure_session, send_mutex,
		                 data.request_id, false, 1,
		                 "unsafe relative path in upload");
		uploads.erase(it);
		return;
	}

	UploadState &state = it->second;
	fs::path target = state.recursive || !data.relative_path.empty()
	                      ? target_for_entry(state.base_path,
	                                         data.relative_path)
	                      : state.base_path;
	std::string error;

	if (data.entry_type == FileEntryType::DIRECTORY) {
		if (!close_open_upload_file(state, error)) {
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1, error);
			return;
		}
		if (!create_directory_at_path(target, error)) {
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1, error);
			return;
		}
		state.directories.emplace_back(target, data.mode);
		if (data.eof) {
			if (!apply_directory_modes(state.directories, error)) {
				send_file_result(socket, secure_session, send_mutex,
				                 data.request_id, false, 1, error);
			} else {
				send_file_result(socket, secure_session, send_mutex,
				                 data.request_id, true, 0, "completed");
			}
			uploads.erase(it);
		}
		return;
	}

	if (!state.stream.is_open() || state.open_path != target) {
		if (!close_open_upload_file(state, error)) {
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1, error);
			return;
		}
		if (!target.parent_path().empty()) {
			if (!fs::exists(target.parent_path())) {
				uploads.erase(it);
				send_file_result(socket, secure_session, send_mutex,
				                 data.request_id, false, 1,
				                 "destination parent does not exist: " +
				                     target.parent_path().string());
				return;
			}
		}
		state.stream.open(target, std::ios::binary | std::ios::trunc);
		if (!state.stream.is_open()) {
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1,
			                 "failed to open destination file");
			return;
		}
		state.open_path = target;
		state.open_mode = data.mode;
	}

	if (!data.data.empty()) {
		state.stream.write(data.data.data(), data.data.size());
		if (!state.stream.good()) {
			state.stream.close();
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1,
			                 "failed while writing destination file");
			return;
		}
	}

	if (data.eof) {
		if (!close_open_upload_file(state, error) ||
		    !apply_directory_modes(state.directories, error)) {
			uploads.erase(it);
			send_file_result(socket, secure_session, send_mutex,
			                 data.request_id, false, 1, error);
			return;
		}
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

	fs::path path = expand_remote_path(request.path);
	std::vector<TransferEntry> entries;
	uint64_t total_size = 0;
	std::string error;
	if (!collect_transfer_entries(path, request.recursive, entries,
	                              total_size, error)) {
		send_file_result(socket, secure_session, send_mutex,
		                 request.request_id, false, 1,
		                 error);
		return;
	}

	uint64_t bytes_sent = 0;
	for (size_t i = 0; i < entries.size(); ++i) {
		if (!send_file_entry(socket, secure_session, send_mutex,
		                     request.request_id, entries[i], total_size,
		                     bytes_sent, i + 1 == entries.size())) {
			send_file_result(socket, secure_session, send_mutex,
			                 request.request_id, false, 1,
			                 "failed to read remote file");
			return;
		}
	}
	send_file_result(socket, secure_session, send_mutex,
	                 request.request_id, true, 0, "completed");
}

void handle_connection(int socket, SecureSession secure_session,
                       uint64_t connection_id,
                       const std::string &authorized_keys_path)
{
	std::mutex send_mutex;
	std::map<uint64_t, UploadState> uploads;
	AuthenticatedUser user;

	if (!authenticate_connection(socket, secure_session, send_mutex,
	                             authorized_keys_path, user)) {
		return;
	}

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
	set_default_config_dir(path_under_executable_dir(argv[0], "xsh-data"));

	ServerOptions options;
	bool show_help = false;
	if (!parse_arguments(argc, argv, options, show_help)) {
		print_usage(argv[0]);
		return 2;
	}
	if (show_help) {
		print_usage(argv[0]);
		return 0;
	}
	if (options.host_key_path.empty()) {
		options.host_key_path = default_host_key_path();
	}
	if (options.authorized_keys_path.empty()) {
		options.authorized_keys_path = default_authorized_keys_path();
	}

	IdentityKey host_identity;
	std::string identity_error;
	if (!load_or_create_ed25519_key(options.host_key_path, host_identity,
	                                identity_error)) {
		LOG(ERROR) << "[Error] " << identity_error;
		return 1;
	}
	LOG(INFO) << "[Info] Host key SHA256:"
	          << fingerprint_sha256(host_identity.public_key);
	LOG(INFO) << "[Info] Authorized keys: "
	          << options.authorized_keys_path;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGCHLD, SIG_IGN);

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
	server_address.sin_port = htons(options.port);

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

	LOG(INFO) << "[Info] xshd is listening on port " << options.port << "...";
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

		uint64_t connection_id = next_connection_id.fetch_add(1);
		pid_t pid = fork();
		if (pid < 0) {
			LOG(ERROR) << "[Error] fork() failed: " << strerror(errno);
			close(client_socket);
			continue;
		}
		if (pid == 0) {
			signal(SIGCHLD, SIG_DFL);
			close(server_socket);
			SecureSession secure_session;
			std::string handshake_error;
			if (!perform_server_handshake(client_socket, secure_session,
			                              host_identity,
			                              handshake_error)) {
				LOG(ERROR) << "[Error] Secure handshake failed: "
				           << handshake_error;
				shutdown(client_socket, SHUT_RDWR);
				close(client_socket);
				_exit(1);
			}
			handle_connection(client_socket, secure_session,
			                  connection_id, options.authorized_keys_path);
			shutdown(client_socket, SHUT_RDWR);
			close(client_socket);
			_exit(0);
		}
		close(client_socket);
	}

	close(server_socket);
	LOG(INFO) << "[Info] Server has shut down.";
	return 0;
}
