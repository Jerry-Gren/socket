// clang-format off
#include <iostream>
#include <string>
#include <cstring>         // For memset
#include <unistd.h>        // For close
#include <sys/socket.h>    // For socket functions
#include <netinet/in.h>    // For sockaddr_in
#include <arpa/inet.h>     // For inet_addr()
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

#include "include/glog_wrapper.h"
#include "include/packet.h"
#include "include/protocol.h"
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

const char *g_prompt = "$ ";

void client_signal_handler(int signum)
{
	LOG(INFO) << "[Cmd] Interrupt signal (" << signum
	          << ") received. Shutting down...";
	g_client_running = false;
	g_cv.notify_all();
}

// Producer thread function
// Receives messages from the server and puts them into the shared queue
void receive_messages(int client_socket)
{
	while (g_client_running) {
		Packet received_pkt;
		if (!read_packet(client_socket, received_pkt)) {
			// read_packet returns false on disconnect or critical error
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
void present_messages()
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
					json data = json::parse(packet_to_show.content);
					std::string from_id = std::to_string(data.value("from_id", 0));
					std::string filename = sanitize_for_terminal(data.value("filename", "unknown"));
					std::string encoded_data = data.value("data", "");
					bool is_eof = data.value("eof", false);

					std::string save_dir = "downloads";
					if (!fs::exists(save_dir)) fs::create_directory(save_dir);

					std::string save_path = save_dir + "/" + from_id + "_" + filename;

					if (is_eof) {
						output = "[File]: Finished receiving file: " + save_path;
					} else {
						std::vector<char> binary_data = base64_decode(encoded_data);

						std::ofstream outfile(save_path, std::ios::binary | std::ios::app);
						outfile.write(binary_data.data(), binary_data.size());
						outfile.close();

						std::cout << "." << std::flush;
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
	          << "---------------------\n";
}

bool send_packet(int socket, const Packet &pkt)
{
	std::vector<char> message_stream = create_message_stream(pkt);
	if (send(socket, message_stream.data(), message_stream.size(), 0) < 0) {
		LOG(ERROR) << "[Error] Failed to send packet: "
		           << MessageTypeToString(pkt.type);
		g_client_running = false;
		g_cv.notify_all();
		return false;
	}
	return true;
}

void on_command_get_time(int socket)
{
	LOG(INFO) << "[Cmd] Requesting server time...";
	Packet pkt;
	pkt.type = MessageType::GET_TIME_REQUEST;
	send_packet(socket, pkt);
}

void on_command_get_name(int socket)
{
	LOG(INFO) << "[Cmd] Requesting server name...";
	Packet pkt;
	pkt.type = MessageType::GET_NAME_REQUEST;
	send_packet(socket, pkt);
}

void on_command_get_list(int socket)
{
	LOG(INFO) << "[Cmd] Requesting client list...";
	Packet pkt;
	pkt.type = MessageType::GET_CLIENT_LIST_REQUEST;
	send_packet(socket, pkt);
}

void on_command_send_message(int socket)
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
	send_packet(socket, pkt);
}

void on_command_send_file(int socket)
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

    if (!fs::exists(filepath)) {
        std::cout << "[Error] File does not exist." << std::endl;
        return;
    }

    std::string filename = fs::path(filepath).filename().string();
    std::ifstream file(filepath, std::ios::binary);

    const size_t CHUNK_SIZE = 32 * 1024;
    std::vector<char> buffer(CHUNK_SIZE);

    LOG(INFO) << "[Cmd] Starting file transfer: " << filename;

    while (file.read(buffer.data(), CHUNK_SIZE) || file.gcount() > 0) {
        size_t bytes_read = file.gcount();
        std::vector<char> chunk_data(buffer.begin(), buffer.begin() + bytes_read);

        std::string encoded_data = base64_encode(chunk_data);

        Packet pkt;
        pkt.type = MessageType::SEND_FILE_REQUEST;
        pkt.content = json{
            {"target_id", target_id},
            {"filename", filename},
            {"data", encoded_data},
            {"eof", false}
        }.dump();

        if (!send_packet(socket, pkt)) return;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    Packet end_pkt;
    end_pkt.type = MessageType::SEND_FILE_REQUEST;
    end_pkt.content = json{
        {"target_id", target_id},
        {"filename", filename},
        {"data", ""},
        {"eof", true}
    }.dump();
    send_packet(socket, end_pkt);

    LOG(INFO) << "[Cmd] File sent complete.";
}

void on_command_disconnect(int socket)
{
	LOG(INFO) << "[Cmd] Sending disconnect request...";
	Packet pkt;
	pkt.type = MessageType::DISCONNECT_REQUEST;
	send_packet(socket, pkt);

	g_client_running = false;
	g_cv.notify_all();
}

void on_force_exit()
{
	LOG(INFO) << "[Cmd] Received Ctrl+D, exiting client...";
	g_client_running = false;
	g_cv.notify_all();
}

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

	signal(SIGINT, client_signal_handler);

	std::string target_ip = SERVER_ADDRESS; // Default is 127.0.0.1
	if (argc > 1) {
		target_ip = argv[1];
	}

	int client_socket;
	struct sockaddr_in server_address;

	// 1. Create socket
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0) {
		LOG(ERROR) << "[Error] Failed to create socket";
		return -1;
	}

	// 2. Set server address
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	// server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
	server_address.sin_addr.s_addr = inet_addr(target_ip.c_str());
	server_address.sin_port = htons(SERVER_PORT);

	// 3. Connect to server
	if (connect(client_socket, (struct sockaddr *)&server_address,
	            sizeof(server_address)) < 0) {
		LOG(ERROR) << "[Error] Connection failed";
		return -1;
	}

	LOG(INFO) << "[Info] Connected to server at " << SERVER_ADDRESS << ":"
	          << SERVER_PORT;

	// Launch the background receiver and presenter threads
	std::thread receiver_thread(receive_messages, client_socket);
	std::thread presenter_thread(present_messages);

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
					on_command_get_time(client_socket);
				} else if (command == "name") {
					on_command_get_name(client_socket);
				} else if (command == "list") {
					on_command_get_list(client_socket);
				} else if (command == "send") {
					on_command_send_message(client_socket);
				} else if (command == "sendfile") {
					on_command_send_file(client_socket);
				} else if (command == "disconnect") {
					on_command_disconnect(client_socket);
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