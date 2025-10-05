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

#include "include/glog_wrapper.h"
#include "include/packet.h"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 4468
// clang-format on

std::mutex g_msg_queue_mutex;
std::condition_variable g_cv;
std::queue<Packet> g_msg_queue;
std::atomic<bool> g_client_running(true);

// Producer thread function
// Receives messages from the server and puts them into the shared queue
void receive_messages(int client_socket)
{
	char buffer[1024];
	while (g_client_running) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(client_socket, &read_fds);

		// Set a timeout for select()
		struct timeval tv;
		tv.tv_sec = 1; // 1 second timeout
		tv.tv_usec = 0;

		// Use select() to wait for data on the socket without blocking
		int activity = select(client_socket + 1, &read_fds, NULL, NULL, &tv);

		// If select() returns an error, but it's not an interrupt from
		// a signal (EINTR), then exit
		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "select() error";
			break;
		}

		// A new connection is pending
		if (activity > 0 && FD_ISSET(client_socket, &read_fds)) {
			ssize_t bytes_received =
			    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
			if (bytes_received > 0) {
				// A message was received, wrap it in a Packet
				std::string message_content(buffer, bytes_received);
				Packet received_packet;
				received_packet.type =
				    MessageType::CHAT_TEXT; // TODO:
				                            // 暂时假设收到的都是聊天消息
				received_packet.content = message_content;
				{
					std::lock_guard<std::mutex> lock(
					    g_msg_queue_mutex);
					g_msg_queue.push(received_packet);
				}
				// Only one consumer can hold the lock
				g_cv.notify_one();
			} else {
				// If recv returns 0 or -1, the server has disconnected
				LOG(INFO) << "[Info] Server disconnected";
				// Every consumer should exit
				g_client_running = false;
				g_cv.notify_all();
				break;
			}
		}
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
			// 这里我们暂时只显示内容
			// \x1b[2K : Erases the entire current line.
			// \r      : Moves the cursor to the beginning of the
			// line.
			std::cout << "\r\x1b[2K[Server]: " << packet_to_show.content
			          << std::endl;
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
				// sending fails, shutdown
				if (send(client_socket, line.c_str(), line.length(), 0) <
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