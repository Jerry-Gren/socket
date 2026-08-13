// clang-format off
#include <atomic>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <string>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "include/file_transfer.h"
#include "include/glog_wrapper.h"
#include "include/auth_protocol.h"
#include "include/identity.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/utility.h"
// clang-format on

#define DEFAULT_SERVER_PORT 4468

namespace fs = std::filesystem;

std::atomic<bool> g_running(true);
std::string g_executable_dir;

struct RemotePath {
	bool remote = false;
	std::string username;
	std::string host;
	std::string path;
};

struct Options {
	bool show_help = false;
	bool recursive = false;
	int port = DEFAULT_SERVER_PORT;
	std::string identity_file;
	std::string known_hosts_file;
	std::vector<RemotePath> sources;
	RemotePath destination;
};

void signal_handler(int)
{
	g_running = false;
}

void print_usage(const char *program)
{
	std::cerr
	    << "Usage:\n"
	    << "  " << program << " [options] source... destination\n"
	    << "\n"
	    << "Copy files through xshd using scp-like paths:\n"
	    << "  " << program << " local.bin user@host:/tmp/local.bin\n"
	    << "  " << program << " user@host:/tmp/remote.bin ./remote.bin\n"
	    << "  " << program << " local1 local2 user@host:/tmp/dir\n"
	    << "  " << program << " user@host:/tmp/a user@host:/tmp/b ./dir\n"
	    << "\n"
	    << "Options:\n"
	    << "  -r, -R            Copy directories recursively\n"
	    << "  -P PORT           xshd port (default 4468)\n"
	    << "  -i FILE           Ed25519 identity file\n"
	    << "  -o OPTION         UserKnownHostsFile=FILE is supported\n"
	    << "  -h, --help        Show this help\n";
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

void split_remote_host(const std::string &destination,
                       std::string &username, std::string &host)
{
	size_t at_pos = destination.rfind('@');
	if (at_pos == std::string::npos) {
		username.clear();
		host = destination;
		return;
	}
	username = destination.substr(0, at_pos);
	host = destination.substr(at_pos + 1);
}

RemotePath parse_path(const std::string &value)
{
	RemotePath parsed;
	size_t colon = value.find(':');
	if (colon == std::string::npos || colon == 0) {
		parsed.remote = false;
		parsed.path = value;
		return parsed;
	}

	std::string maybe_host = value.substr(0, colon);
	std::string maybe_path = value.substr(colon + 1);
	if (maybe_host.find('/') != std::string::npos || maybe_path.empty()) {
		parsed.remote = false;
		parsed.path = value;
		return parsed;
	}

	parsed.remote = true;
	split_remote_host(maybe_host, parsed.username, parsed.host);
	parsed.path = maybe_path;
	return parsed;
}

bool apply_option(const std::string &option, Options &options)
{
	auto equals = option.find('=');
	std::string key = equals == std::string::npos
	                      ? option
	                      : option.substr(0, equals);
	std::string value = equals == std::string::npos
	                        ? ""
	                        : option.substr(equals + 1);
	if (key == "UserKnownHostsFile") {
		if (value.empty()) {
			std::cerr << "xcp: invalid UserKnownHostsFile\n";
			return false;
		}
		options.known_hosts_file = value;
	}
	return true;
}

bool parse_arguments(int argc, char *argv[], Options &options)
{
	int i = 1;
	for (; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg.empty() || arg[0] != '-' || arg == "-") {
			break;
		}
		if (arg == "-h" || arg == "--help") {
			options.show_help = true;
			return true;
		}
		if (arg == "-r" || arg == "-R") {
			options.recursive = true;
			continue;
		}
		if (arg == "-P" || arg == "-i" || arg == "-o") {
			if (++i >= argc) {
				std::cerr << "xcp: " << arg << " requires an argument\n";
				return false;
			}
			if (arg == "-i") {
				options.identity_file = argv[i];
				continue;
			}
			if (arg == "-o") {
				return apply_option(argv[i], options);
			}
			if (!parse_port(argv[i], options.port)) {
				std::cerr << "xcp: invalid port\n";
				return false;
			}
			continue;
		}
		std::cerr << "xcp: unsupported option: " << arg << "\n";
		return false;
	}

	if (argc - i < 2) {
		std::cerr << "xcp: expected source and destination\n";
		return false;
	}

	options.destination = parse_path(argv[argc - 1]);
	for (int source_index = i; source_index < argc - 1; ++source_index) {
		options.sources.push_back(parse_path(argv[source_index]));
	}
	if (options.sources.empty()) {
		std::cerr << "xcp: expected at least one source\n";
		return false;
	}

	bool sources_are_remote = options.sources.front().remote;
	for (const auto &source : options.sources) {
		if (source.remote != sources_are_remote) {
			std::cerr << "xcp: mixed local and remote sources are not supported\n";
			return false;
		}
	}
	if (sources_are_remote == options.destination.remote) {
		std::cerr << "xcp: exactly one path must be remote\n";
		return false;
	}
	if (sources_are_remote) {
		const RemotePath &first = options.sources.front();
		std::string first_username =
		    first.username.empty() ? default_username() : first.username;
		for (const auto &source : options.sources) {
			std::string source_username =
			    source.username.empty() ? default_username() : source.username;
			if (source.host != first.host ||
			    source_username != first_username) {
				std::cerr
				    << "xcp: remote sources must use the same user and host\n";
				return false;
			}
		}
	}
	return true;
}

bool connect_secure(const std::string &host, int port, int &socket_fd,
                    const std::string &known_hosts_path,
                    SecureSession &secure_session)
{
	struct addrinfo hints;
	struct addrinfo *results = nullptr;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	std::string port_str = std::to_string(port);
	int gai_result = getaddrinfo(host.c_str(), port_str.c_str(), &hints,
	                             &results);
	if (gai_result != 0) {
		std::cerr << "xcp: failed to resolve " << host << ": "
		          << gai_strerror(gai_result) << "\n";
		return false;
	}

	socket_fd = -1;
	for (struct addrinfo *addr = results; addr != nullptr;
	     addr = addr->ai_next) {
		int candidate =
		    socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (candidate < 0) {
			continue;
		}
		if (connect(candidate, addr->ai_addr, addr->ai_addrlen) == 0) {
			socket_fd = candidate;
			break;
		}
		close(candidate);
	}
	freeaddrinfo(results);

	if (socket_fd < 0) {
		std::cerr << "xcp: connection failed\n";
		return false;
	}

	std::string error;
	if (!perform_client_handshake(socket_fd, secure_session, host, port,
	                              known_hosts_path, error)) {
		std::cerr << "xcp: secure handshake failed: " << error << "\n";
		close(socket_fd);
		return false;
	}
	return true;
}

bool authenticate_user(int socket_fd, SecureSession &secure_session,
                       const std::string &username,
                       const std::string &identity_file)
{
	IdentityKey identity;
	std::string error;
	if (!load_or_create_ed25519_key(identity_file, identity, error)) {
		std::cerr << "xcp: " << error << "\n";
		return false;
	}

	std::string message = create_user_auth_message(
	    secure_session.session_id, username, identity.public_key);
	std::string signature;
	if (!sign_ed25519(identity.key.get(), message, signature)) {
		std::cerr << "xcp: failed to sign authentication request\n";
		return false;
	}

	Packet request;
	request.type = MessageType::AUTH_REQUEST;
	request.content = create_auth_request_payload(
	    username, identity.public_key, signature);
	if (!send_secure_packet(socket_fd, secure_session, request)) {
		std::cerr << "xcp: failed to send authentication request\n";
		return false;
	}

	Packet response;
	if (!read_secure_packet(socket_fd, secure_session, response) ||
	    response.type != MessageType::AUTH_RESULT) {
		std::cerr << "xcp: authentication failed: invalid response\n";
		return false;
	}
	AuthResultPayload result;
	if (!parse_auth_result_payload(response.content, result) ||
	    !result.success) {
		std::cerr << "xcp: authentication failed";
		if (!result.message.empty()) {
			std::cerr << ": " << result.message;
		}
		std::cerr << "\n";
		std::cerr << "xcp: public key: ed25519 "
		          << hex_encode(identity.public_key) << "\n";
		return false;
	}
	return true;
}

std::string format_duration(std::chrono::seconds duration)
{
	uint64_t total_seconds = static_cast<uint64_t>(duration.count());
	uint64_t hours = total_seconds / 3600;
	uint64_t minutes = (total_seconds % 3600) / 60;
	uint64_t seconds = total_seconds % 60;

	std::ostringstream oss;
	oss << (hours < 10 ? "0" : "") << hours << ":"
	    << (minutes < 10 ? "0" : "") << minutes << ":"
	    << (seconds < 10 ? "0" : "") << seconds;
	return oss.str();
}

std::string estimate_eta(uint64_t done, uint64_t total,
                         std::chrono::steady_clock::time_point started_at)
{
	if (total == 0 || done >= total) {
		return "00:00:00";
	}
	auto now = std::chrono::steady_clock::now();
	std::chrono::duration<long double> elapsed = now - started_at;
	if (done == 0 || elapsed.count() <= 0.0L) {
		return "--:--:--";
	}
	long double rate = static_cast<long double>(done) / elapsed.count();
	if (rate <= 0.0L) {
		return "--:--:--";
	}
	long double remaining = static_cast<long double>(total - done) / rate;
	return format_duration(std::chrono::seconds(
	    static_cast<int64_t>(std::ceil(remaining))));
}

void print_progress(uint64_t done, uint64_t total,
                    std::chrono::steady_clock::time_point started_at,
                    int &last_percent)
{
	int percent = total == 0 ? 100 : static_cast<int>(
	    (static_cast<long double>(std::min(done, total)) * 100.0L) /
	    static_cast<long double>(total));
	if (percent == last_percent) {
		return;
	}
	last_percent = percent;
	std::cerr << "\r\x1b[2K" << percent << "% ETA "
	          << estimate_eta(done, total, started_at) << std::flush;
	if (done >= total) {
		std::cerr << "\n";
	}
}

struct TransferEntry {
	fs::path path;
	std::string relative_path;
	FileEntryType type = FileEntryType::REGULAR_FILE;
	uint32_t mode = 0644;
	uint64_t size = 0;
};

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

std::string path_basename(const std::string &value)
{
	std::string trimmed = value;
	while (trimmed.size() > 1 &&
	       (trimmed.back() == '/' || trimmed.back() == '\\')) {
		trimmed.pop_back();
	}
	fs::path path(trimmed);
	std::string name = path.filename().string();
	return name.empty() ? "file" : name;
}

bool has_trailing_separator(const std::string &path)
{
	return !path.empty() && (path.back() == '/' || path.back() == '\\');
}

std::string join_remote_child(const std::string &parent,
                              const std::string &child)
{
	if (parent.empty() || parent == ".") {
		return child;
	}
	if (has_trailing_separator(parent)) {
		return parent + child;
	}
	return parent + "/" + child;
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
		entry.size = 0;
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
		error = "source does not exist";
		return false;
	}
	if (fs::is_regular_file(source, ec)) {
		return append_transfer_entry(source, "", entries, total_size, error);
	}
	if (!fs::is_directory(source, ec)) {
		error = "source is not a regular file or directory";
		return false;
	}
	if (!recursive) {
		error = source.string() + " is a directory (use -r)";
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

bool chmod_path(const fs::path &path, uint32_t mode)
{
	std::error_code ec;
	fs::permissions(path, static_cast<fs::perms>(mode & 07777),
	                fs::perm_options::replace, ec);
	if (ec) {
		std::cerr << "xcp: failed to set permissions on " << path
		          << ": " << ec.message() << "\n";
		return false;
	}
	return true;
}

fs::path target_for_entry(const fs::path &root, const std::string &relative)
{
	if (relative.empty()) {
		return root;
	}
	return root / fs::path(relative);
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

bool apply_directory_modes(
    const std::vector<std::pair<fs::path, uint32_t>> &directories)
{
	for (auto it = directories.rbegin(); it != directories.rend(); ++it) {
		if (!chmod_path(it->first, it->second)) {
			return false;
		}
	}
	return true;
}

bool create_directory_at_path(const fs::path &path)
{
	std::error_code ec;
	if (fs::exists(path, ec)) {
		if (fs::is_directory(path, ec)) {
			return true;
		}
		std::cerr << "xcp: destination exists and is not a directory: "
		          << path << "\n";
		return false;
	}
	if (!path.parent_path().empty() && !fs::exists(path.parent_path(), ec)) {
		std::cerr << "xcp: destination parent does not exist: "
		          << path.parent_path() << "\n";
		return false;
	}
	if (!fs::create_directory(path, ec)) {
		std::cerr << "xcp: failed to create directory " << path
		          << ": " << ec.message() << "\n";
		return false;
	}
	return true;
}

bool send_file_entry(int socket_fd, SecureSession &secure_session,
                     uint64_t request_id, const TransferEntry &entry,
                     uint64_t total_size, uint64_t &bytes_sent,
                     bool last_entry,
                     std::chrono::steady_clock::time_point started_at,
                     int &last_percent)
{
	if (entry.type == FileEntryType::DIRECTORY || entry.size == 0) {
		Packet pkt;
		pkt.type = MessageType::FILE_DATA;
		pkt.content = create_file_data_payload(
		    request_id, total_size, bytes_sent, entry.type, entry.mode,
		    entry.relative_path, last_entry, "");
		return send_secure_packet(socket_fd, secure_session, pkt);
	}

	std::ifstream file(entry.path, std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "xcp: failed to open source file: "
		          << entry.path << "\n";
		return false;
	}

	size_t chunk_size = calculate_file_chunk_size(total_size);
	std::string buffer(chunk_size, '\0');
	while (g_running &&
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
		if (!send_secure_packet(socket_fd, secure_session, pkt)) {
			return false;
		}
		print_progress(bytes_sent, total_size, started_at, last_percent);
	}
	return true;
}

bool read_file_result(int socket_fd, SecureSession &secure_session,
                      uint64_t request_id)
{
	while (g_running) {
		Packet response;
		if (!read_secure_packet(socket_fd, secure_session, response)) {
			return false;
		}
		if (response.type != MessageType::FILE_RESULT) {
			continue;
		}
		FileResultPayload result;
		if (!parse_file_result_payload(response.content, result) ||
		    result.request_id != request_id) {
			continue;
		}
		if (!result.success) {
			std::cerr << "xcp: " << result.message << "\n";
		}
		return result.success;
	}
	return false;
}

bool send_file_upload(int socket_fd, SecureSession &secure_session,
                      const fs::path &source, const std::string &remote_path,
                      bool recursive)
{
	std::vector<TransferEntry> entries;
	uint64_t total_size = 0;
	std::string error;
	if (!collect_transfer_entries(source, recursive, entries, total_size,
	                              error)) {
		std::cerr << "xcp: " << error << "\n";
		return false;
	}

	uint64_t request_id = 1;
	std::string destination_path = remote_path;
	if (has_trailing_separator(destination_path)) {
		destination_path += path_basename(source.string());
	}
	bool source_is_directory = fs::is_directory(source);

	Packet request_pkt;
	request_pkt.type = MessageType::FILE_PUT_REQUEST;
	request_pkt.content = create_file_request_payload(
	    request_id, total_size, source_is_directory, destination_path);
	if (!send_secure_packet(socket_fd, secure_session, request_pkt)) {
		return false;
	}
	if (!read_file_result(socket_fd, secure_session, request_id)) {
		return false;
	}

	uint64_t bytes_sent = 0;
	auto started_at = std::chrono::steady_clock::now();
	int last_percent = -1;
	print_progress(0, total_size, started_at, last_percent);
	for (size_t i = 0; i < entries.size(); ++i) {
		if (!send_file_entry(socket_fd, secure_session, request_id,
		                     entries[i], total_size, bytes_sent,
		                     i + 1 == entries.size(), started_at,
		                     last_percent)) {
			return false;
		}
	}

	if (entries.empty() || !entries.back().size) {
		print_progress(total_size, total_size, started_at, last_percent);
	}

	return read_file_result(socket_fd, secure_session, request_id);
}

bool receive_file_download(int socket_fd, SecureSession &secure_session,
                           const std::string &remote_path,
                           const fs::path &destination, bool recursive)
{
	uint64_t request_id = 1;
	Packet request_pkt;
	request_pkt.type = MessageType::FILE_GET_REQUEST;
	request_pkt.content = create_file_request_payload(
	    request_id, 0, recursive, remote_path);
	if (!send_secure_packet(socket_fd, secure_session, request_pkt)) {
		return false;
	}

	std::error_code ec;
	bool destination_is_directory =
	    fs::exists(destination, ec) && fs::is_directory(destination, ec);
	fs::path root_path;
	fs::path single_file_path = destination_is_directory
	                                ? destination / path_basename(remote_path)
	                                : destination;
	bool root_path_initialized = false;
	std::ofstream output;
	fs::path open_path;
	uint32_t open_mode = 0644;
	std::vector<std::pair<fs::path, uint32_t>> directories;

	uint64_t total_size = 0;
	uint64_t bytes_received = 0;
	auto started_at = std::chrono::steady_clock::now();
	int last_percent = -1;

	while (g_running) {
		Packet pkt;
		if (!read_secure_packet(socket_fd, secure_session, pkt)) {
			return false;
		}
		if (pkt.type == MessageType::FILE_RESULT) {
			if (output.is_open()) {
				output.close();
				if (!chmod_path(open_path, open_mode)) {
					return false;
				}
			}
			if (!apply_directory_modes(directories)) {
				return false;
			}
			FileResultPayload result;
			if (!parse_file_result_payload(pkt.content, result) ||
			    result.request_id != request_id) {
				continue;
			}
			if (!result.success) {
				std::cerr << "xcp: " << result.message << "\n";
			}
			return result.success;
		}
		if (pkt.type != MessageType::FILE_DATA) {
			continue;
		}

		FileDataPayload data;
		if (!parse_file_data_payload(pkt.content, data) ||
		    data.request_id != request_id) {
			continue;
		}
		if (!is_safe_relative_path(data.relative_path)) {
			std::cerr << "xcp: unsafe relative path in transfer\n";
			return false;
		}
		if (!root_path_initialized) {
			if (data.entry_type == FileEntryType::DIRECTORY ||
			    !data.relative_path.empty()) {
				root_path = destination_is_directory
				                ? destination / path_basename(remote_path)
				                : destination;
			} else {
				root_path = single_file_path;
			}
			root_path_initialized = true;
		}
		fs::path target =
		    data.entry_type == FileEntryType::DIRECTORY ||
		            !data.relative_path.empty()
		        ? target_for_entry(root_path, data.relative_path)
		        : single_file_path;
		total_size = data.total_size;
		if (data.entry_type == FileEntryType::DIRECTORY) {
			if (output.is_open()) {
				output.close();
				if (!chmod_path(open_path, open_mode)) {
					return false;
				}
			}
			if (!create_directory_at_path(target)) {
				return false;
			}
			directories.emplace_back(target, data.mode);
			bytes_received = data.bytes_sent;
			print_progress(bytes_received, total_size, started_at,
			               last_percent);
			continue;
		}
		if (!output.is_open() || open_path != target) {
			if (output.is_open()) {
				output.close();
				if (!chmod_path(open_path, open_mode)) {
					return false;
				}
			}
			if (!target.parent_path().empty()) {
				if (!fs::exists(target.parent_path())) {
					std::cerr << "xcp: destination parent does not exist: "
					          << target.parent_path() << "\n";
					return false;
				}
			}
			output.open(target, std::ios::binary | std::ios::trunc);
			if (!output.is_open()) {
				std::cerr << "xcp: failed to open destination file "
				          << target << "\n";
				return false;
			}
			open_path = target;
			open_mode = data.mode;
		}
		if (!data.data.empty()) {
			output.write(data.data.data(), data.data.size());
			if (!output.good()) {
				std::cerr << "xcp: failed writing destination file\n";
				return false;
			}
		}
		bytes_received = data.bytes_sent;
		print_progress(bytes_received, total_size, started_at,
		               last_percent);
	}
	return false;
}

int main(int argc, char *argv[])
{
	Options options;
	if (!parse_arguments(argc, argv, options)) {
		print_usage(argv[0]);
		return 2;
	}
	if (options.show_help) {
		print_usage(argv[0]);
		return 0;
	}

	auto glog = GlogWrapper(argv[0], false);
	g_executable_dir = executable_dir(argv[0]);
	set_default_config_dir((fs::path(g_executable_dir) / "xsh-data").string());
	if (options.identity_file.empty()) {
		options.identity_file = default_user_key_path();
	}
	if (options.known_hosts_file.empty()) {
		options.known_hosts_file = default_known_hosts_path();
	}
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	bool sources_are_remote = options.sources.front().remote;
	bool multiple_sources = options.sources.size() > 1;
	if (sources_are_remote && multiple_sources) {
		std::error_code ec;
		if (!fs::exists(options.destination.path, ec) ||
		    !fs::is_directory(options.destination.path, ec)) {
			std::cerr
			    << "xcp: local destination must be an existing directory "
			       "when copying multiple remote sources\n";
			return 2;
		}
	}

	std::string host = sources_are_remote ? options.sources.front().host
	                                      : options.destination.host;
	std::string username = sources_are_remote
	                           ? options.sources.front().username
	                           : options.destination.username;
	if (username.empty()) {
		username = default_username();
	}
	int socket_fd = -1;
	SecureSession secure_session;
	if (!connect_secure(host, options.port, socket_fd,
	                    options.known_hosts_file, secure_session)) {
		return 1;
	}
	if (!authenticate_user(socket_fd, secure_session, username,
	                       options.identity_file)) {
		shutdown(socket_fd, SHUT_RDWR);
		close(socket_fd);
		return 1;
	}

	bool success = false;
	if (!sources_are_remote) {
		success = true;
		for (const auto &source : options.sources) {
			std::string remote_destination = options.destination.path;
			if (multiple_sources) {
				remote_destination = join_remote_child(
				    remote_destination, path_basename(source.path));
			}
			if (!send_file_upload(socket_fd, secure_session,
			                      source.path, remote_destination,
			                      options.recursive)) {
				success = false;
				break;
			}
		}
	} else {
		success = true;
		for (const auto &source : options.sources) {
			if (!receive_file_download(socket_fd, secure_session,
			                           source.path,
			                           options.destination.path,
			                           options.recursive)) {
				success = false;
				break;
			}
		}
	}

	Packet disconnect;
	disconnect.type = MessageType::DISCONNECT_REQUEST;
	send_secure_packet(socket_fd, secure_session, disconnect);
	shutdown(socket_fd, SHUT_RDWR);
	close(socket_fd);
	return success ? 0 : 1;
}
