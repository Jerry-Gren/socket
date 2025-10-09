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

#include "include/glog_wrapper.h"
#include "include/packet.h"
#include "include/protocol.h"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 4468

using json = nlohmann::json;
// clang-format on

std::mutex g_msg_queue_mutex;
std::condition_variable g_cv;
std::queue<Packet> g_msg_queue;
std::atomic<bool> g_client_running(true);

// Producer thread function
// Receives messages from the server and puts them into the shared queue
void receive_messages(int client_socket)
{
	while (g_client_running) {
		std::vector<char> length_buffer;
		// 1. Read the 4-byte total length prefix
		if (!read_n_bytes(client_socket, 4, length_buffer)) {
			if (g_client_running) { // Avoid error message on clean shutdown
				LOG(INFO) << "[Info] Server disconnected.";
			}
			g_client_running = false;
			g_cv.notify_all();
			break;
		}
		uint32_t total_len = ntohl(*reinterpret_cast<uint32_t*>(length_buffer.data()));

		// 2. Read the rest of the packet data
		std::vector<char> packet_data_buffer;
		if (!read_n_bytes(client_socket, total_len, packet_data_buffer)) {
			LOG(ERROR) << "[Error] Failed to read packet data from server.";
			g_client_running = false;
			g_cv.notify_all();
			break;
		}

		// 3. Parse and push to queue
		if (packet_data_buffer.size() < HEADER_SIZE) continue;
		uint32_t magic = ntohl(*reinterpret_cast<uint32_t*>(packet_data_buffer.data()));
		if (magic != MAGIC_NUMBER) continue;

		Packet received_pkt;
		received_pkt.type = static_cast<MessageType>(packet_data_buffer[4]);
		uint32_t payload_len = ntohl(*reinterpret_cast<uint32_t*>(packet_data_buffer.data() + 8));
		if (payload_len > 0) {
			received_pkt.content.assign(packet_data_buffer.data() + HEADER_SIZE, payload_len);
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
			// TODO: 现在可以根据 packet 的类型来决定如何显示
			std::string output;
			std::string type_str = MessageTypeToString(packet_to_show.type);

			// Format different types of messages
			switch (packet_to_show.type) {
				case MessageType::SYSTEM_NOTICE_INDICATION:
				case MessageType::GET_TIME_RESPONSE:
				case MessageType::GET_NAME_RESPONSE:
				case MessageType::GET_CLIENT_LIST_RESPONSE:
				case MessageType::SEND_MESSAGE_RESPONSE:
				case MessageType::MESSAGE_INDICATION:
					// Try to parse JSON for all types of messages
					try {
						json data = json::parse(packet_to_show.content);
						// [Server | TYPE]: Pretty-printed JSON content
						output = "[Server | " + type_str + "]:\n" + data.dump(4); // dump(4) for pretty printing with 4 spaces
					} catch (const json::parse_error& e) {
						// If JSON parse fails, print error and content
						output = "[Server | " + type_str + " | JSON PARSE ERROR]: " + e.what() + "\nRaw content: " + packet_to_show.content;
					}
					break;

				default:
					// For unknown or unhandled types, print type and content
					output = "[Server | " + type_str + " | UNHANDLED]: " + packet_to_show.content;
					break;
			}
			// \x1b[2K : Erases the entire current line.
			// \r      : Moves the cursor to the beginning of the
			// line.
			std::cout << "\r\x1b[2K" << output << std::endl;
			std::cout << "Enter message ('exit' to quit): " << std::flush;
		}
	}
	LOG(INFO) << "[Info] Presenter thread finished";
}

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

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
	server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
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
	std::string line;
	std::cout << "Enter message ('exit' to quit): " << std::flush;
	while (g_client_running) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(STDIN_FILENO, &read_fds);

		// Set a timeout for select()
		struct timeval tv;
		tv.tv_sec = 1; // 1 second timeout
		tv.tv_usec = 0;

		// Use select to wait for keyboard input with a timeout.
		int activity = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &tv);

		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "select() error on stdin";
			break;
		}

		// If there is keyboard input, read and send it.
		if (activity > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
			std::string line;
			if (std::getline(std::cin, line)) {
				// user types "exit", shutdown
				if (line == "exit") {
					g_client_running = false;
					g_cv.notify_all();
					break;
				}

				Packet pkt_to_send;
				pkt_to_send.type = MessageType::SEND_MESSAGE_REQUEST;
				pkt_to_send.content = json{{"message", line}}.dump();

				std::vector<char> message_stream = create_message_stream(pkt_to_send);

				if (send(client_socket, message_stream.data(), message_stream.size(), 0) <
				    0) {
					LOG(ERROR) << "[Error] Failed to send message";
					g_client_running = false;
					g_cv.notify_all();
					break;
				}
				std::cout << "Enter message ('exit' to quit): "
				          << std::flush;
			} else {
				// If stdin is closed (e.g., Ctrl+D), shutdown
				g_client_running = false;
				g_cv.notify_all();
				break;
			}
		}
	}

	LOG(INFO) << "[Info] Shutting down...";
	// Shut down the socket to unblock the receiver thread from select/recv
	shutdown(client_socket, SHUT_RDWR);
	close(client_socket);
	// Wait for the threads to finish their work
	receiver_thread.join();
	presenter_thread.join();
	LOG(INFO) << "[Info] Client has shut down";
}