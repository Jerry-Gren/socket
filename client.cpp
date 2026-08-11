// clang-format off
#include <iostream>
#include <string>
#include <cstring>         // For memset
#include <unistd.h>        // For close
#include <sys/socket.h>    // For socket functions
#include <netinet/in.h>    // For sockaddr_in
#include <arpa/inet.h>     // For inet_addr()
#include <netdb.h>         // For getaddrinfo()
#include <thread>          // For threading
#include <mutex>           // For std::mutex
#include <condition_variable> // For std::condition_variable
#include <queue>           // For std::queue
#include <nlohmann/json.hpp>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <fstream>
#include <filesystem>
#include <map>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <memory>

#include "include/glog_wrapper.h"
#include "include/file_transfer.h"
#include "include/packet.h"
#include "include/protocol.h"
#include "include/secure_channel.h"
#include "include/shell_exec.h"
#include "include/utility.h"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 4468

using json = nlohmann::json;
namespace fs = std::filesystem;
// clang-format on

std::mutex g_msg_queue_mutex;
std::condition_variable g_cv;
std::queue<Packet> g_msg_queue;
std::atomic<bool> g_client_running(true);
std::atomic<uint64_t> g_next_shell_request_id(1);
std::mutex g_send_mutex;

const char *g_prompt = "$ ";
constexpr size_t SHELL_STREAM_CHUNK_SIZE = 32 * 1024;

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

struct RemoteExecOptions {
	bool enabled = false;
	bool show_help = false;
	bool forward_stdin = true;
	bool quiet = false;
	bool request_tty = false;
	bool relay_to_client = false;
	uint32_t timeout_seconds = 0;
	int server_port = SERVER_PORT;
	std::string server_ip = SERVER_ADDRESS;
	std::string destination;
	uint64_t target_id = 0;
	std::string command;
};

std::mutex g_shell_input_mutex;
std::map<ShellInputKey, std::shared_ptr<ShellInputQueue>> g_shell_inputs;

bool send_packet(int socket, SecureSession &secure_session, const Packet &pkt);
void run_shell_exec_request(int socket, SecureSession *secure_session,
                            ShellExecRequestPayload request,
                            std::shared_ptr<ShellInputQueue> input_queue);

void client_signal_handler(int signum)
{
	LOG(INFO) << "[Cmd] Interrupt signal (" << signum
	          << ") received. Shutting down...";
	g_client_running = false;
	g_cv.notify_all();
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

bool push_shell_input(const ShellExecStdinPayload &payload)
{
	std::shared_ptr<ShellInputQueue> queue;
	{
		std::lock_guard<std::mutex> lock(g_shell_input_mutex);
		auto it = g_shell_inputs.find(
		    ShellInputKey{payload.peer_id, payload.request_id});
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

// Producer thread function
// Receives messages from the server and puts them into the shared queue
void receive_messages(int client_socket, SecureSession *secure_session)
{
	while (g_client_running) {
		Packet received_pkt;
		if (!read_secure_packet(client_socket, *secure_session, received_pkt)) {
			// read_secure_packet returns false on disconnect or critical error
			if (g_client_running) { // Avoid error message on clean shutdown
				LOG(INFO) << "[Info] Server disconnected.";
			}
			g_client_running = false; // Signal other threads to stop
			g_cv.notify_all();        // Wake up presenter thread to exit
			break;
		}

		{
			std::lock_guard<std::mutex> lock(g_msg_queue_mutex);
			g_msg_queue.push(received_pkt);
		}
		g_cv.notify_one();
	}
	LOG(INFO) << "[Info] Receiver thread finished";
}

// Consumer thread function
// Takes packets from the shared queue and displays them to the user
void present_messages(int client_socket, SecureSession *secure_session)
{
	while (g_client_running) {
		Packet packet_to_show;
		bool has_message = false;
		{
			std::unique_lock<std::mutex> lock(g_msg_queue_mutex);
			// Wait until the queue is not empty or the client is shutting
			// down. The while loop protects against spurious wakeups
			while (g_msg_queue.empty() && g_client_running) {
				g_cv.wait(lock);
			}

			if (!g_client_running && g_msg_queue.empty()) {
				break;
			}

			if (!g_msg_queue.empty()) {
				packet_to_show = g_msg_queue.front();
				g_msg_queue.pop();
				has_message = true;
			}
		}

		if (has_message) {
			std::string output;
			std::string type_str = MessageTypeToString(packet_to_show.type);

			// Format different types of messages
			switch (packet_to_show.type) {
			case MessageType::GET_TIME_RESPONSE:
				try {
					json data = json::parse(packet_to_show.content);
					output =
					    "[Server Time]: " + data.value("time", "...");
				} catch (const json::parse_error &) {
					output = "[Server Time]: (Parse Error)";
				}
				break;
			case MessageType::GET_NAME_RESPONSE:
				try {
					json data = json::parse(packet_to_show.content);
					output =
					    "[Server Name]: " + data.value("name", "...");
				} catch (const json::parse_error &) {
					output = "[Server Name]: (Parse Error)";
				}
				break;
			case MessageType::GET_CLIENT_LIST_RESPONSE:
				try {
					json data = json::parse(packet_to_show.content);
					std::ostringstream oss;
					oss << "[Client List]:\n"
					    << "  ID  | IP Address      | Port\n"
					    << "-----------------------------------";
					for (const auto &client : data.at("clients")) {
						oss << "\n  " << std::setw(3) << std::left
						    << client.value("id", 0) << " | "
						    << std::setw(15) << std::left
						    << client.value("ip", "...") << " | "
						    << client.value("port", 0);
					}
					output = oss.str();
				} catch (const json::parse_error &) {
					output = "[Client List]: (Parse Error)";
				}
				break;
			case MessageType::SEND_MESSAGE_RESPONSE:
				try {
					json data = json::parse(packet_to_show.content);
					if (data.value("status", "") == "success") {
						output = "[Info]: Message sent to ID " +
						         std::to_string(
						             data.value("target_id", 0)) +
						         " successfully.";
					} else {
						output = "[Error]: Failed to send "
						         "message. Reason: " +
						         data.value("message",
						                    "Unknown error");
					}
				} catch (const json::parse_error &) {
					output = "[Info]: (Send Status Parse Error)";
				}
				break;
			case MessageType::FILE_INDICATION:
				try {
					FileTransferPayload file_payload;
					if (!parse_file_transfer_payload(packet_to_show.content,
					                                 file_payload)) {
						output = "[File Error]: Invalid file payload";
						break;
					}

					std::string from_id =
					    std::to_string(file_payload.peer_id);
					std::string filename =
					    fs::path(file_payload.filename).filename().string();
					if (filename.empty()) {
						filename = "unknown";
					}

					std::string save_dir = "downloads";
					if (!fs::exists(save_dir)) fs::create_directory(save_dir);

					std::string save_path = save_dir + "/" + from_id + "_" + filename;
					std::string transfer_key = save_path;
					static std::map<std::string, std::ofstream> open_files;

					if (file_payload.eof) {
						auto file_it = open_files.find(transfer_key);
						if (file_it != open_files.end()) {
							file_it->second.close();
							open_files.erase(file_it);
						} else if (file_payload.total_size == 0) {
							std::ofstream empty_file(save_path, std::ios::binary);
							empty_file.close();
						}
						output = "[File]: Finished receiving file: " +
						         sanitize_for_terminal(save_path);
					} else {
						auto [file_it, inserted] = open_files.try_emplace(transfer_key);
						if (inserted) {
							file_it->second.open(save_path,
							                     std::ios::binary | std::ios::trunc);
						}
						if (!file_it->second.is_open()) {
							output = "[File Error]: Failed to open " +
							         sanitize_for_terminal(save_path);
							break;
						}
						file_it->second.write(file_payload.data.data(),
						                      file_payload.data.size());
						continue;
					}

				} catch (const std::exception &e) {
					output = "[File Error]: " + std::string(e.what());
				}
				break;
			case MessageType::MESSAGE_INDICATION:
				try {
					json data = json::parse(packet_to_show.content);
					std::string from =
					    std::to_string(data.value("from_id", 0));
					output = "[Message from " + from +
					         "]: " + data.value("message", "...");
				} catch (const json::parse_error &) {
					output = "[Message]: (Parse Error)";
				}
				break;
			case MessageType::SHELL_EXEC_REQUEST:
				try {
					ShellExecRequestPayload request;
					if (!parse_shell_exec_request_payload(packet_to_show.content,
					                                      request)) {
						output = "[Shell Error]: Invalid exec request";
						break;
					}
					auto input_queue = register_shell_input_queue(
					    ShellInputKey{request.peer_id, request.request_id});
					std::thread(run_shell_exec_request, client_socket,
					            secure_session, request, input_queue)
					    .detach();
					continue;
				} catch (const std::exception &e) {
					output = "[Shell Error]: " + std::string(e.what());
				}
				break;
			case MessageType::SHELL_EXEC_STDIN:
				try {
					ShellExecStdinPayload shell_input;
					if (!parse_shell_exec_stdin_payload(packet_to_show.content,
					                                    shell_input)) {
						output = "[Shell Error]: Invalid stdin payload";
						break;
					}
					push_shell_input(shell_input);
					continue;
				} catch (const std::exception &e) {
					output = "[Shell Error]: " + std::string(e.what());
				}
				break;
			case MessageType::SHELL_EXEC_OUTPUT:
				try {
					ShellExecOutputPayload shell_output;
					if (!parse_shell_exec_output_payload(packet_to_show.content,
					                                     shell_output)) {
						output = "[Shell Error]: Invalid output payload";
						break;
					}
					std::string stream =
					    shell_output.stream == ShellOutputStream::STDOUT
					        ? "stdout"
					        : "stderr";
					output = "[Shell from " + std::to_string(shell_output.peer_id) +
					         " #" + std::to_string(shell_output.request_id) +
					         " " + stream + "]:\n" +
					         sanitize_for_terminal(shell_output.data);
				} catch (const std::exception &e) {
					output = "[Shell Error]: " + std::string(e.what());
				}
				break;
			case MessageType::SHELL_EXEC_RESULT:
				try {
					ShellExecResultPayload result;
					if (!parse_shell_exec_result_payload(packet_to_show.content,
					                                     result)) {
						output = "[Shell Error]: Invalid result payload";
						break;
					}
					output = "[Shell from " + std::to_string(result.peer_id) +
					         " #" + std::to_string(result.request_id) +
					         "]: exit=" + std::to_string(result.exit_code);
					if (result.timed_out) {
						output += " timeout";
					}
					if (!result.message.empty()) {
						output += " (" + sanitize_for_terminal(result.message) + ")";
					}
				} catch (const std::exception &e) {
					output = "[Shell Error]: " + std::string(e.what());
				}
				break;
			case MessageType::SERVER_SHUTDOWN_INDICATION:
				try {
					json data = json::parse(packet_to_show.content);
					output =
					    "[Server Shutdown]: " + data.value("notice", "Server is shutting down.");
				} catch (const json::parse_error &) {
					output = "[Server Shutdown]: (Parse Error)";
				}
				// No more to do
				// receiver_thread will stop afterward
				break;
			case MessageType::SYSTEM_NOTICE_INDICATION:
				try {
					json data = json::parse(packet_to_show.content);
					output =
					    "[System]: " + data.value("notice", "...");
				} catch (const json::parse_error &) {
					output = "[System]: (Parse Error)";
				}
				break;

			default:
				// For unknown or unhandled types, print type and content
				try {
					json data = json::parse(packet_to_show.content);
					output = "[Server | " + type_str +
					         " | UNHANDLED]:\n" + data.dump(4);
				} catch (const json::parse_error &) {
					output =
					    "[Server | " + type_str +
					    " | UNHANDLED]: " + packet_to_show.content;
				}
				break;
			}
			// \x1b[2K : Erases the entire current line.
			// \r      : Moves the cursor to the beginning of the
			// line.
			std::cout << "\r\x1b[2K" << output << std::endl;
			std::cout << g_prompt << std::flush;
		}
	}
	LOG(INFO) << "[Info] Presenter thread finished";
}

void on_command_help()
{
	std::cout << "--- Client Help ---\n"
	          << "  help       - Show this help message\n"
	          << "  time       - Request server time\n"
	          << "  name       - Request server name\n"
	          << "  list       - Request client list\n"
	          << "  send       - Send a message to a client\n"
		  << "  sendfile   - Send a file to a client\n"
	          << "  disconnect - Disconnect from server and exit\n"
	          << "\nRemote command mode:\n"
	          << "  client [options] <client-id> <command> [args...]\n"
	          << "---------------------\n";
}

bool send_packet(int socket, SecureSession &secure_session, const Packet &pkt)
{
	std::lock_guard<std::mutex> lock(g_send_mutex);
	if (!send_secure_packet(socket, secure_session, pkt)) {
		LOG(ERROR) << "[Error] Failed to send packet: "
		           << MessageTypeToString(pkt.type);
		g_client_running = false;
		g_cv.notify_all();
		return false;
	}
	return true;
}

void run_shell_exec_request(int socket, SecureSession *secure_session,
                            ShellExecRequestPayload request,
                            std::shared_ptr<ShellInputQueue> input_queue)
{
	ShellInputKey input_key{request.peer_id, request.request_id};

	auto on_output = [&](ShellOutputStream stream, const std::string &data) {
		if (!g_client_running || data.empty()) {
			return;
		}
		Packet output_pkt;
		output_pkt.type = MessageType::SHELL_EXEC_OUTPUT;
		output_pkt.content = create_shell_exec_output_payload(
		    request.peer_id, request.request_id, stream, data);
		send_packet(socket, *secure_session, output_pkt);
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
	    request.peer_id, request.request_id, result.exit_code,
	    result.timed_out, result.message);
	send_packet(socket, *secure_session, result_pkt);
}

void on_command_get_time(int socket, SecureSession &secure_session)
{
	LOG(INFO) << "[Cmd] Requesting server time...";
	Packet pkt;
	pkt.type = MessageType::GET_TIME_REQUEST;
	send_packet(socket, secure_session, pkt);
}

void on_command_get_name(int socket, SecureSession &secure_session)
{
	LOG(INFO) << "[Cmd] Requesting server name...";
	Packet pkt;
	pkt.type = MessageType::GET_NAME_REQUEST;
	send_packet(socket, secure_session, pkt);
}

void on_command_get_list(int socket, SecureSession &secure_session)
{
	LOG(INFO) << "[Cmd] Requesting client list...";
	Packet pkt;
	pkt.type = MessageType::GET_CLIENT_LIST_REQUEST;
	send_packet(socket, secure_session, pkt);
}

void on_command_send_message(int socket, SecureSession &secure_session)
{
	uint64_t target_id;
	std::string message;
	std::string temp_id_input;

	std::cout << "Enter target client ID: " << std::flush;
	if (!std::getline(std::cin, temp_id_input)) {
		return;
	}

	long long signed_target_id;
	size_t pos_after_parse;

	try {
		signed_target_id = std::stoll(temp_id_input, &pos_after_parse);
	} catch (const std::invalid_argument &e) {
		std::cout << "[Error] Invalid ID. Must be a number." << std::endl;
		return;
	} catch (const std::out_of_range &e) {
		std::cout << "[Error] ID is too large." << std::endl;
		return;
	}

	if (pos_after_parse != temp_id_input.length()) {
		std::cout << "[Error] Invalid ID. Contains non-numeric characters." << std::endl;
		return;
	}

	if (signed_target_id <= 0) {
		std::cout << "[Error] Invalid ID. Client ID must be a positive number." << std::endl;
		return;
	}

	target_id = static_cast<uint64_t>(signed_target_id);

	std::cout << "Enter message: " << std::flush;
	if (!std::getline(std::cin, message) || message.empty()) {
		std::cout << "[Info] Message canceled." << std::endl;
		return;
	}

	LOG(INFO) << "[Cmd] Sending message to ID " << target_id;
	Packet pkt;
	pkt.type = MessageType::SEND_MESSAGE_REQUEST;
	pkt.content = json{{"target_id", target_id}, {"message", message}}.dump();
	send_packet(socket, secure_session, pkt);
}

void on_command_send_file(int socket, SecureSession &secure_session)
{
    uint64_t target_id;
    std::string filepath, temp_id_input;

    std::cout << "Enter target client ID: " << std::flush;
    if (!std::getline(std::cin, temp_id_input)) return;
    try {
        target_id = std::stoull(temp_id_input);
    } catch (...) {
        std::cout << "[Error] Invalid ID." << std::endl; return;
    }

    std::cout << "Enter file path to send: " << std::flush;
    if (!std::getline(std::cin, filepath)) return;

    if (!fs::exists(filepath) || !fs::is_regular_file(filepath)) {
        std::cout << "[Error] File does not exist or is not a regular file." << std::endl;
        return;
    }

    std::string filename = fs::path(filepath).filename().string();
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[Error] Failed to open file." << std::endl;
        return;
    }
    uint64_t total_size = fs::file_size(filepath);
    uint64_t bytes_sent = 0;

    size_t chunk_size = calculate_file_chunk_size(total_size);
    std::string buffer(chunk_size, '\0');

    LOG(INFO) << "[Cmd] Starting file transfer: " << filename;

    while (file.read(buffer.data(), chunk_size) || file.gcount() > 0) {
        size_t bytes_read = file.gcount();
        bytes_sent += bytes_read;
        std::string chunk_data(buffer.data(), bytes_read);

        Packet pkt;
        pkt.type = MessageType::SEND_FILE_REQUEST;
        pkt.content = create_file_transfer_payload(
            target_id, total_size, bytes_sent, false, filename, chunk_data);

        if (!send_packet(socket, secure_session, pkt)) return;
    }

    Packet end_pkt;
    end_pkt.type = MessageType::SEND_FILE_REQUEST;
    end_pkt.content = create_file_transfer_payload(
        target_id, total_size, total_size, true, filename, "");
    send_packet(socket, secure_session, end_pkt);

    LOG(INFO) << "[Cmd] File sent complete.";
}

void on_command_disconnect(int socket, SecureSession &secure_session)
{
	LOG(INFO) << "[Cmd] Sending disconnect request...";
	Packet pkt;
	pkt.type = MessageType::DISCONNECT_REQUEST;
	send_packet(socket, secure_session, pkt);

	g_client_running = false;
	g_cv.notify_all();
}

void on_force_exit()
{
	LOG(INFO) << "[Cmd] Received Ctrl+D, exiting client...";
	g_client_running = false;
	g_cv.notify_all();
}

void print_usage(const char *program)
{
	std::cerr
	    << "Usage:\n"
	    << "  " << program << " [server_ip]\n"
	    << "  " << program << " [options] destination command [argument ...]\n"
	    << "\n"
	    << "Remote command mode follows the common ssh shape. destination is a "
	       "server host\n"
	    << "or user@server_host. The command runs on that server host.\n"
	    << "\n"
	    << "Options:\n"
	    << "  --server HOST      Relay server address for --target-client mode\n"
	    << "  --target-client ID Execute on a connected client through the relay\n"
	    << "  -p PORT           Server port (default 4468)\n"
	    << "  -l USER           Accept ssh-style login name; currently ignored\n"
	    << "  -n                Do not read from stdin\n"
	    << "  -T                Disable pseudo-terminal allocation\n"
	    << "  -t                Accepted for ssh compatibility; PTY is not implemented\n"
	    << "  -q                Quiet mode\n"
	    << "  -o OPTION         Accept ssh-style options; RemoteCommandTimeout=N is supported\n"
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
		return out > 0;
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

bool apply_ssh_option(const std::string &option, RemoteExecOptions &options)
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
	}
	return true;
}

bool parse_client_arguments(int argc, char *argv[], RemoteExecOptions &options)
{
	if (const char *server_env = std::getenv("SOCKET_SERVER")) {
		if (*server_env != '\0') {
			options.server_ip = server_env;
		}
	}

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
		if (arg == "--server" || arg == "--target-client") {
			if (++i >= argc) {
				std::cerr << arg << " requires an argument\n";
				return false;
			}
			if (arg == "--server") {
				options.server_ip = argv[i];
			} else {
				if (!parse_u64(argv[i], options.target_id)) {
					std::cerr << "Invalid target client ID: " << argv[i]
					          << "\n";
					return false;
				}
				options.relay_to_client = true;
			}
			continue;
		}
		if (arg == "-p" || arg == "-l" || arg == "-o") {
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
				options.server_port = port;
			} else if (arg == "-o" &&
			           !apply_ssh_option(argv[i], options)) {
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

	int remaining = argc - i;
	if (remaining <= 0) {
		if (options.relay_to_client) {
			std::cerr << "Missing remote command\n";
			return false;
		}
		options.enabled = false;
		return true;
	}

	if (remaining == 1) {
		uint64_t maybe_target = 0;
		std::string host = destination_host_part(argv[i]);
		if (options.relay_to_client || parse_u64(host, maybe_target)) {
			std::cerr << "Interactive remote login is not implemented; "
			          << "provide a command.\n";
			return false;
		}
		options.server_ip = argv[i];
		options.enabled = false;
		return true;
	}

	options.enabled = true;
	if (options.relay_to_client) {
		options.command = join_command_arguments(i, argc, argv);
		if (options.command.empty()) {
			std::cerr << "Missing remote command\n";
			return false;
		}
		return true;
	}

	options.destination = argv[i];
	std::string host = destination_host_part(options.destination);
	uint64_t legacy_target_id = 0;
	if (parse_u64(host, legacy_target_id)) {
		options.relay_to_client = true;
		options.target_id = legacy_target_id;
	} else {
		options.server_ip = host;
		options.target_id = 0;
	}
	options.command = join_command_arguments(i + 1, argc, argv);
	if (options.command.empty()) {
		std::cerr << "Missing remote command\n";
		return false;
	}
	return true;
}

bool connect_secure(const RemoteExecOptions &options, int &client_socket,
                    SecureSession &secure_session)
{
	struct addrinfo hints;
	struct addrinfo *results = nullptr;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	std::string port = std::to_string(options.server_port);
	int gai_result = getaddrinfo(options.server_ip.c_str(), port.c_str(),
	                             &hints, &results);
	if (gai_result != 0) {
		LOG(ERROR) << "[Error] Failed to resolve " << options.server_ip
		           << ": " << gai_strerror(gai_result);
		return false;
	}

	client_socket = -1;
	for (struct addrinfo *addr = results; addr != nullptr;
	     addr = addr->ai_next) {
		int candidate =
		    socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (candidate < 0) {
			continue;
		}
		if (connect(candidate, addr->ai_addr, addr->ai_addrlen) == 0) {
			client_socket = candidate;
			break;
		}
		close(candidate);
	}
	freeaddrinfo(results);

	if (client_socket < 0) {
		LOG(ERROR) << "[Error] Connection failed";
		return false;
	}

	LOG(INFO) << "[Info] Connected to server at " << options.server_ip << ":"
	          << options.server_port;

	if (!perform_client_handshake(client_socket, secure_session)) {
		LOG(ERROR) << "[Error] Secure handshake failed";
		close(client_socket);
		return false;
	}
	LOG(INFO) << "[Info] Secure channel established.";
	return true;
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

bool send_shell_stdin(int socket, SecureSession &secure_session,
                      uint64_t target_id, uint64_t request_id, bool eof,
                      const std::string &data)
{
	Packet pkt;
	pkt.type = MessageType::SHELL_EXEC_STDIN;
	pkt.content =
	    create_shell_exec_stdin_payload(target_id, request_id, eof, data);
	return send_packet(socket, secure_session, pkt);
}

void stream_local_stdin(int socket, SecureSession *secure_session,
                        uint64_t target_id, uint64_t request_id)
{
	std::string buffer(SHELL_STREAM_CHUNK_SIZE, '\0');
	while (g_client_running) {
		ssize_t count = read(STDIN_FILENO, buffer.data(), buffer.size());
		if (count > 0) {
			if (!send_shell_stdin(socket, *secure_session, target_id,
			                      request_id, false,
			                      std::string(buffer.data(), count))) {
				return;
			}
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}
	send_shell_stdin(socket, *secure_session, target_id, request_id, true, "");
}

int normalize_remote_exit_code(const ShellExecResultPayload &result)
{
	if (result.exit_code >= 0 && result.exit_code <= 255) {
		return result.exit_code;
	}
	return 255;
}

int run_remote_exec(int client_socket, SecureSession &secure_session,
                    const RemoteExecOptions &options)
{
	if (options.request_tty && !options.quiet) {
		std::cerr << "Pseudo-terminal allocation is not implemented; "
		          << "running without a PTY.\n";
	}

	uint64_t request_id = g_next_shell_request_id.fetch_add(1);
	Packet request_pkt;
	request_pkt.type = MessageType::SHELL_EXEC_REQUEST;
	request_pkt.content = create_shell_exec_request_payload(
	    options.target_id, request_id, options.timeout_seconds,
	    options.command);
	if (!send_packet(client_socket, secure_session, request_pkt)) {
		return 255;
	}

	bool should_forward_stdin =
	    options.forward_stdin && !isatty(STDIN_FILENO);
	if (should_forward_stdin) {
		std::thread(stream_local_stdin, client_socket, &secure_session,
		            options.target_id, request_id)
		    .detach();
	} else {
		send_shell_stdin(client_socket, secure_session, options.target_id,
		                 request_id, true, "");
	}

	while (g_client_running) {
		Packet pkt;
		if (!read_secure_packet(client_socket, secure_session, pkt)) {
			std::cerr << "Connection closed before remote command finished\n";
			return 255;
		}

		switch (pkt.type) {
		case MessageType::SHELL_EXEC_OUTPUT: {
			ShellExecOutputPayload output;
			if (!parse_shell_exec_output_payload(pkt.content, output) ||
			    output.request_id != request_id ||
			    output.peer_id != options.target_id) {
				continue;
			}
			int fd = output.stream == ShellOutputStream::STDOUT
			             ? STDOUT_FILENO
			             : STDERR_FILENO;
			if (!write_all_fd(fd, output.data)) {
				return 255;
			}
			break;
		}
		case MessageType::SHELL_EXEC_RESULT: {
			ShellExecResultPayload result;
			if (!parse_shell_exec_result_payload(pkt.content, result) ||
			    result.request_id != request_id ||
			    result.peer_id != options.target_id) {
				continue;
			}
			if (result.timed_out || result.message != "completed") {
				if (!result.message.empty()) {
					std::cerr << result.message << "\n";
				}
			}
			return normalize_remote_exit_code(result);
		}
		case MessageType::SERVER_SHUTDOWN_INDICATION:
			std::cerr << "Server shut down before remote command finished\n";
			return 255;
		default:
			break;
		}
	}
	return 255;
}

int main(int argc, char *argv[])
{
	RemoteExecOptions options;
	if (!parse_client_arguments(argc, argv, options)) {
		print_usage(argv[0]);
		return 2;
	}
	if (options.show_help) {
		print_usage(argv[0]);
		return 0;
	}

	auto glog = GlogWrapper(argv[0], !options.enabled);

	signal(SIGINT, client_signal_handler);
	signal(SIGPIPE, SIG_IGN);

	int client_socket;
	SecureSession secure_session;
	if (!connect_secure(options, client_socket, secure_session)) {
		return -1;
	}

	if (options.enabled) {
		int exit_code =
		    run_remote_exec(client_socket, secure_session, options);
		g_client_running = false;
		shutdown(client_socket, SHUT_RDWR);
		close(client_socket);
		return exit_code;
	}

	// Launch the background receiver and presenter threads
	std::thread receiver_thread(receive_messages, client_socket,
	                            &secure_session);
	std::thread presenter_thread(present_messages, client_socket,
	                             &secure_session);

	// Main loop for handling user input
	// Uses select() to avoid blocking on std::getline
	while (g_client_running) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(STDIN_FILENO, &read_fds);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int activity = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &tv);

		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "select() error on stdin";
			break;
		}

		if (activity > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
			std::string command;
			if (std::getline(std::cin, command)) {

				if (command == "help") {
					on_command_help();
				} else if (command == "time") {
					on_command_get_time(client_socket, secure_session);
				} else if (command == "name") {
					on_command_get_name(client_socket, secure_session);
				} else if (command == "list") {
					on_command_get_list(client_socket, secure_session);
				} else if (command == "send") {
					on_command_send_message(client_socket, secure_session);
				} else if (command == "sendfile") {
					on_command_send_file(client_socket, secure_session);
				} else if (command == "disconnect") {
					on_command_disconnect(client_socket, secure_session);
				} else if (command.empty()) {
				} else {
					std::cout << "[Error] Unknown command: '"
					          << command << "'" << std::endl;
				}

				if (g_client_running) {
					std::cout << g_prompt << std::flush;
				}

			} else {
				// Ctrl+D shutdown
				on_force_exit();
				break;
			}
		}
	}

	LOG(INFO) << "[Info] Client is shutting down. Closing client socket";
	// Shut down the socket to unblock the receiver thread from select/recv
	shutdown(client_socket, SHUT_RDWR);
	close(client_socket);
	// Wait for the threads to finish their work
	receiver_thread.join();
	presenter_thread.join();
	LOG(INFO) << "[Info] Client has shut down";
}
