// clang-format off
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <netdb.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "include/glog_wrapper.h"
#include "include/auth_protocol.h"
#include "include/identity.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/shell_exec.h"
#include "include/utility.h"
// clang-format on

#define DEFAULT_SERVER_ADDRESS "127.0.0.1"
#define DEFAULT_SERVER_PORT 4468

constexpr size_t SHELL_STREAM_CHUNK_SIZE = 32 * 1024;

std::atomic<bool> g_running(true);
std::atomic<uint64_t> g_next_request_id(1);
std::mutex g_send_mutex;

struct RemoteExecOptions {
	bool show_help = false;
	bool forward_stdin = true;
	bool quiet = false;
	bool request_tty = false;
	uint32_t timeout_seconds = 0;
	int port = DEFAULT_SERVER_PORT;
	std::string host = DEFAULT_SERVER_ADDRESS;
	std::string username;
	std::string identity_file;
	std::string known_hosts_file;
	std::string destination;
	std::string command;
};

void signal_handler(int)
{
	g_running = false;
}

void print_usage(const char *program)
{
	std::cerr
	    << "Usage:\n"
	    << "  " << program << " [options] destination command [argument ...]\n"
	    << "\n"
	    << "destination is host or user@host. The command runs on xshd at "
	       "that host.\n"
	    << "\n"
	    << "Options:\n"
	    << "  -p PORT           xshd port (default 4468)\n"
	    << "  -l USER           Login user\n"
	    << "  -i FILE           Ed25519 identity file\n"
	    << "  -n                Do not read from stdin\n"
	    << "  -T                Disable pseudo-terminal allocation\n"
	    << "  -t                Accepted for ssh compatibility; PTY is not implemented\n"
	    << "  -q                Quiet mode\n"
	    << "  -o OPTION         RemoteCommandTimeout=N and UserKnownHostsFile=FILE are supported\n"
	    << "  -h, --help        Show this help\n";
}

bool parse_u64(const std::string &value, uint64_t &out)
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
		out = std::stoull(value);
		return true;
	} catch (...) {
		return false;
	}
}

bool parse_int_range(const std::string &value, int min_value, int max_value,
                     int &out)
{
	uint64_t parsed = 0;
	if (!parse_u64(value, parsed) || parsed > static_cast<uint64_t>(max_value) ||
	    parsed < static_cast<uint64_t>(min_value)) {
		return false;
	}
	out = static_cast<int>(parsed);
	return true;
}

std::string destination_host_part(const std::string &destination)
{
	size_t at_pos = destination.rfind('@');
	if (at_pos == std::string::npos) {
		return destination;
	}
	return destination.substr(at_pos + 1);
}

std::string join_command_arguments(int start, int argc, char *argv[])
{
	std::ostringstream oss;
	for (int i = start; i < argc; ++i) {
		if (i != start) {
			oss << ' ';
		}
		oss << argv[i];
	}
	return oss.str();
}

bool apply_option(const std::string &option, RemoteExecOptions &options)
{
	auto equals = option.find('=');
	std::string key = equals == std::string::npos
	                      ? option
	                      : option.substr(0, equals);
	std::string value = equals == std::string::npos
	                        ? ""
	                        : option.substr(equals + 1);
	if (key == "RemoteCommandTimeout") {
		int timeout = 0;
		if (!parse_int_range(value, 0, 86400, timeout)) {
			std::cerr << "Invalid RemoteCommandTimeout: " << value << "\n";
			return false;
		}
		options.timeout_seconds = static_cast<uint32_t>(timeout);
	} else if (key == "UserKnownHostsFile") {
		if (value.empty()) {
			std::cerr << "Invalid UserKnownHostsFile\n";
			return false;
		}
		options.known_hosts_file = value;
	}
	return true;
}

bool parse_arguments(int argc, char *argv[], RemoteExecOptions &options)
{
	int i = 1;
	bool options_done = false;

	for (; i < argc; ++i) {
		std::string arg = argv[i];
		if (options_done || arg.empty() || arg[0] != '-' || arg == "-") {
			break;
		}
		if (arg == "--") {
			options_done = true;
			continue;
		}
		if (arg == "-h" || arg == "--help") {
			options.show_help = true;
			return true;
		}
		if (arg == "-p" || arg == "-l" || arg == "-i" || arg == "-o") {
			if (++i >= argc) {
				std::cerr << arg << " requires an argument\n";
				return false;
			}
			if (arg == "-p") {
				int port = 0;
				if (!parse_int_range(argv[i], 1, 65535, port)) {
					std::cerr << "Invalid port: " << argv[i] << "\n";
					return false;
				}
				options.port = port;
			} else if (arg == "-l") {
				options.username = argv[i];
			} else if (arg == "-i") {
				options.identity_file = argv[i];
			} else if (!apply_option(argv[i], options)) {
				return false;
			}
			continue;
		}
		if (arg == "-n") {
			options.forward_stdin = false;
			continue;
		}
		if (arg == "-T") {
			options.request_tty = false;
			continue;
		}
		bool only_t = arg.size() > 1;
		for (size_t j = 1; j < arg.size(); ++j) {
			if (arg[j] != 't') {
				only_t = false;
				break;
			}
		}
		if (only_t) {
			options.request_tty = true;
			continue;
		}
		if (arg == "-q") {
			options.quiet = true;
			continue;
		}
		std::cerr << "Unsupported option: " << arg << "\n";
		return false;
	}

	if (argc - i < 2) {
		std::cerr << "Missing destination or command\n";
		return false;
	}

	options.destination = argv[i];
	options.host = destination_host_part(options.destination);
	size_t at_pos = options.destination.rfind('@');
	if (at_pos != std::string::npos && options.username.empty()) {
		options.username = options.destination.substr(0, at_pos);
	}
	if (options.username.empty()) {
		options.username = default_username();
	}
	options.command = join_command_arguments(i + 1, argc, argv);
	return !options.host.empty() && !options.command.empty();
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
		std::cerr << "xsh: failed to resolve " << host << ": "
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
		std::cerr << "xsh: connection failed\n";
		return false;
	}

	std::string error;
	if (!perform_client_handshake(socket_fd, secure_session, host, port,
	                              known_hosts_path, error)) {
		std::cerr << "xsh: secure handshake failed: " << error << "\n";
		close(socket_fd);
		return false;
	}
	return true;
}

bool authenticate_user(int socket_fd, SecureSession &secure_session,
                       const RemoteExecOptions &options)
{
	IdentityKey identity;
	std::string error;
	if (!load_or_create_ed25519_key(options.identity_file, identity, error)) {
		std::cerr << "xsh: " << error << "\n";
		return false;
	}

	std::string message = create_user_auth_message(
	    secure_session.session_id, options.username, identity.public_key);
	std::string signature;
	if (!sign_ed25519(identity.key.get(), message, signature)) {
		std::cerr << "xsh: failed to sign authentication request\n";
		return false;
	}

	Packet request;
	request.type = MessageType::AUTH_REQUEST;
	request.content = create_auth_request_payload(
	    options.username, identity.public_key, signature);
	if (!send_secure_packet(socket_fd, secure_session, request)) {
		std::cerr << "xsh: failed to send authentication request\n";
		return false;
	}

	Packet response;
	if (!read_secure_packet(socket_fd, secure_session, response) ||
	    response.type != MessageType::AUTH_RESULT) {
		std::cerr << "xsh: authentication failed: invalid response\n";
		return false;
	}
	AuthResultPayload result;
	if (!parse_auth_result_payload(response.content, result) ||
	    !result.success) {
		std::cerr << "xsh: authentication failed";
		if (!result.message.empty()) {
			std::cerr << ": " << result.message;
		}
		std::cerr << "\n";
		std::cerr << "xsh: public key: ed25519 "
		          << hex_encode(identity.public_key) << "\n";
		return false;
	}
	return true;
}

bool send_packet(int socket_fd, SecureSession &secure_session,
                 const Packet &pkt)
{
	std::lock_guard<std::mutex> lock(g_send_mutex);
	return send_secure_packet(socket_fd, secure_session, pkt);
}

bool write_all_fd(int fd, const std::string &data)
{
	size_t written_total = 0;
	while (written_total < data.size()) {
		ssize_t written =
		    write(fd, data.data() + written_total,
		          data.size() - written_total);
		if (written > 0) {
			written_total += static_cast<size_t>(written);
			continue;
		}
		if (written < 0 && errno == EINTR) {
			continue;
		}
		return false;
	}
	return true;
}

void stream_local_stdin(int socket_fd, SecureSession *secure_session,
                        uint64_t request_id)
{
	std::string buffer(SHELL_STREAM_CHUNK_SIZE, '\0');
	while (g_running) {
		ssize_t count = read(STDIN_FILENO, buffer.data(), buffer.size());
		if (count > 0) {
			Packet pkt;
			pkt.type = MessageType::SHELL_EXEC_STDIN;
			pkt.content = create_shell_exec_stdin_payload(
			    0, request_id, false, std::string(buffer.data(), count));
			if (!send_packet(socket_fd, *secure_session, pkt)) {
				return;
			}
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}

	Packet eof_pkt;
	eof_pkt.type = MessageType::SHELL_EXEC_STDIN;
	eof_pkt.content =
	    create_shell_exec_stdin_payload(0, request_id, true, "");
	send_packet(socket_fd, *secure_session, eof_pkt);
}

int normalize_exit_code(const ShellExecResultPayload &result)
{
	if (result.exit_code >= 0 && result.exit_code <= 255) {
		return result.exit_code;
	}
	return 255;
}

int run_remote_exec(int socket_fd, SecureSession &secure_session,
                    const RemoteExecOptions &options)
{
	if (options.request_tty && !options.quiet) {
		std::cerr << "xsh: pseudo-terminal allocation is not implemented; "
		          << "running without a PTY\n";
	}

	uint64_t request_id = g_next_request_id.fetch_add(1);
	Packet request_pkt;
	request_pkt.type = MessageType::SHELL_EXEC_REQUEST;
	request_pkt.content = create_shell_exec_request_payload(
	    0, request_id, options.timeout_seconds, options.command);
	if (!send_packet(socket_fd, secure_session, request_pkt)) {
		return 255;
	}

	if (options.forward_stdin && !isatty(STDIN_FILENO)) {
		std::thread(stream_local_stdin, socket_fd, &secure_session,
		            request_id)
		    .detach();
	} else {
		Packet eof_pkt;
		eof_pkt.type = MessageType::SHELL_EXEC_STDIN;
		eof_pkt.content =
		    create_shell_exec_stdin_payload(0, request_id, true, "");
		send_packet(socket_fd, secure_session, eof_pkt);
	}

	while (g_running) {
		Packet pkt;
		if (!read_secure_packet(socket_fd, secure_session, pkt)) {
			std::cerr << "xsh: connection closed before command finished\n";
			return 255;
		}

		if (pkt.type == MessageType::SHELL_EXEC_OUTPUT) {
			ShellExecOutputPayload output;
			if (!parse_shell_exec_output_payload(pkt.content, output) ||
			    output.request_id != request_id) {
				continue;
			}
			int fd = output.stream == ShellOutputStream::STDOUT
			             ? STDOUT_FILENO
			             : STDERR_FILENO;
			if (!write_all_fd(fd, output.data)) {
				return 255;
			}
		} else if (pkt.type == MessageType::SHELL_EXEC_RESULT) {
			ShellExecResultPayload result;
			if (!parse_shell_exec_result_payload(pkt.content, result) ||
			    result.request_id != request_id) {
				continue;
			}
			if (result.timed_out || result.message != "completed") {
				if (!result.message.empty()) {
					std::cerr << "xsh: " << result.message << "\n";
				}
			}
			return normalize_exit_code(result);
		}
	}
	return 255;
}

int main(int argc, char *argv[])
{
	RemoteExecOptions options;
	if (!parse_arguments(argc, argv, options)) {
		print_usage(argv[0]);
		return 2;
	}
	if (options.show_help) {
		print_usage(argv[0]);
		return 0;
	}

	auto glog = GlogWrapper(argv[0], false);
	set_default_config_dir(path_under_executable_dir(argv[0], "xsh-data"));
	if (options.identity_file.empty()) {
		options.identity_file = default_user_key_path();
	}
	if (options.known_hosts_file.empty()) {
		options.known_hosts_file = default_known_hosts_path();
	}
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	int socket_fd = -1;
	SecureSession secure_session;
	if (!connect_secure(options.host, options.port, socket_fd,
	                    options.known_hosts_file,
	                    secure_session)) {
		return 255;
	}
	if (!authenticate_user(socket_fd, secure_session, options)) {
		shutdown(socket_fd, SHUT_RDWR);
		close(socket_fd);
		return 255;
	}

	int exit_code = run_remote_exec(socket_fd, secure_session, options);
	g_running = false;
	shutdown(socket_fd, SHUT_RDWR);
	close(socket_fd);
	return exit_code;
}
