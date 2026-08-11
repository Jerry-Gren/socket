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
#include <sys/socket.h>
#include <unistd.h>

#include "include/file_transfer.h"
#include "include/glog_wrapper.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
// clang-format on

#define DEFAULT_SERVER_PORT 4468

namespace fs = std::filesystem;

std::atomic<bool> g_running(true);

struct RemotePath {
	bool remote = false;
	std::string host;
	std::string path;
};

struct Options {
	bool show_help = false;
	int port = DEFAULT_SERVER_PORT;
	RemotePath source;
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
	    << "  " << program << " [options] source destination\n"
	    << "\n"
	    << "Copy files through xshd using scp-like paths:\n"
	    << "  " << program << " local.bin user@host:/tmp/local.bin\n"
	    << "  " << program << " user@host:/tmp/remote.bin ./remote.bin\n"
	    << "\n"
	    << "Options:\n"
	    << "  -P PORT           xshd port (default 4468)\n"
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

std::string host_part(const std::string &destination)
{
	size_t at_pos = destination.rfind('@');
	if (at_pos == std::string::npos) {
		return destination;
	}
	return destination.substr(at_pos + 1);
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
	parsed.host = host_part(maybe_host);
	parsed.path = maybe_path;
	return parsed;
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
		if (arg == "-P") {
			if (++i >= argc || !parse_port(argv[i], options.port)) {
				std::cerr << "xcp: invalid port\n";
				return false;
			}
			continue;
		}
		std::cerr << "xcp: unsupported option: " << arg << "\n";
		return false;
	}

	if (argc - i != 2) {
		std::cerr << "xcp: expected source and destination\n";
		return false;
	}

	options.source = parse_path(argv[i]);
	options.destination = parse_path(argv[i + 1]);
	if (options.source.remote == options.destination.remote) {
		std::cerr << "xcp: exactly one path must be remote\n";
		return false;
	}
	return true;
}

bool connect_secure(const std::string &host, int port, int &socket_fd,
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

	if (!perform_client_handshake(socket_fd, secure_session)) {
		std::cerr << "xcp: secure handshake failed\n";
		close(socket_fd);
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

bool send_file_upload(int socket_fd, SecureSession &secure_session,
                      const fs::path &source, const std::string &remote_path)
{
	if (!fs::exists(source) || !fs::is_regular_file(source)) {
		std::cerr << "xcp: source is not a regular file\n";
		return false;
	}

	uint64_t request_id = 1;
	uint64_t total_size = fs::file_size(source);
	std::ifstream file(source, std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "xcp: failed to open source file\n";
		return false;
	}

	Packet request_pkt;
	request_pkt.type = MessageType::FILE_PUT_REQUEST;
	request_pkt.content = create_file_request_payload(
	    request_id, total_size, remote_path);
	if (!send_secure_packet(socket_fd, secure_session, request_pkt)) {
		return false;
	}

	size_t chunk_size = calculate_file_chunk_size(total_size);
	std::string buffer(chunk_size, '\0');
	uint64_t bytes_sent = 0;
	auto started_at = std::chrono::steady_clock::now();
	int last_percent = -1;

	while (g_running &&
	       (file.read(buffer.data(), chunk_size) || file.gcount() > 0)) {
		size_t bytes_read = static_cast<size_t>(file.gcount());
		bytes_sent += bytes_read;

		Packet data_pkt;
		data_pkt.type = MessageType::FILE_DATA;
		data_pkt.content = create_file_data_payload(
		    request_id, total_size, bytes_sent, false,
		    std::string(buffer.data(), bytes_read));
		if (!send_secure_packet(socket_fd, secure_session, data_pkt)) {
			return false;
		}
		print_progress(bytes_sent, total_size, started_at, last_percent);
	}

	Packet eof_pkt;
	eof_pkt.type = MessageType::FILE_DATA;
	eof_pkt.content = create_file_data_payload(
	    request_id, total_size, total_size, true, "");
	if (!send_secure_packet(socket_fd, secure_session, eof_pkt)) {
		return false;
	}

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

bool receive_file_download(int socket_fd, SecureSession &secure_session,
                           const std::string &remote_path,
                           const fs::path &destination)
{
	uint64_t request_id = 1;
	Packet request_pkt;
	request_pkt.type = MessageType::FILE_GET_REQUEST;
	request_pkt.content =
	    create_file_request_payload(request_id, 0, remote_path);
	if (!send_secure_packet(socket_fd, secure_session, request_pkt)) {
		return false;
	}

	fs::path output_path = destination;
	std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
	if (!output.is_open()) {
		std::cerr << "xcp: failed to open destination file\n";
		return false;
	}

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
		total_size = data.total_size;
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
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	std::string host = options.source.remote ? options.source.host
	                                         : options.destination.host;
	int socket_fd = -1;
	SecureSession secure_session;
	if (!connect_secure(host, options.port, socket_fd, secure_session)) {
		return 1;
	}

	bool success = false;
	if (!options.source.remote) {
		success = send_file_upload(socket_fd, secure_session,
		                           options.source.path,
		                           options.destination.path);
	} else {
		success = receive_file_download(socket_fd, secure_session,
		                                options.source.path,
		                                options.destination.path);
	}

	Packet disconnect;
	disconnect.type = MessageType::DISCONNECT_REQUEST;
	send_secure_packet(socket_fd, secure_session, disconnect);
	shutdown(socket_fd, SHUT_RDWR);
	close(socket_fd);
	return success ? 0 : 1;
}
