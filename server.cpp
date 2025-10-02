// clang-format off
#include <iostream>
#include <string>
#include <cstring>         // For memset
#include <unistd.h>        // For close
#include <sys/socket.h>    // For socket functions
#include <netinet/in.h>    // For sockaddr_in
#include <thread>          // For threading
#include <csignal>         // For signal handling
#include <atomic>          // For std::atomic
#include <sys/select.h>    // For select()
#include <cerrno>          // For errno

#define SERVER_PORT 4468
#define MAX_CLIENT_QUEUE 20

#include "include/glog_wrapper.h"
// clang-format on

std::atomic<bool> g_server_running(true);

// Signal handler function
// Called when SIGINT (Ctrl+C) or SIGTERM (kill) is received
void signal_handler(int signum)
{
	LOG(INFO) << "[Info] Interrupt signal (" << signum
	          << ") received. Shutting down...";
	g_server_running = false;
}

// Client handler function
// This function is executed in a separate thread for each new connection
void handle_client(int client_socket)
{
	LOG(INFO) << "[Info] Handling client on socket " << client_socket;
	// Send greeting message to client and close connection
	const char *greeting_message = "Hello from server!";
	send(client_socket, greeting_message, strlen(greeting_message), 0);
	// std::this_thread::sleep_for(std::chrono::seconds(30));
	close(client_socket);
	LOG(INFO) << "[Info] Finished handling client on socket "
	          << client_socket;
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
	LOG(INFO) << "[Info] Server is listening on port " << SERVER_PORT
	          << "...";

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
		// without blocking.
		int activity =
		    select(server_socket + 1, &read_fds, NULL, NULL, &tv);

		// If select() returns an error, but it's not an interrupt from
		// a signal (EINTR), then exit
		if ((activity < 0) && (errno != EINTR)) {
			LOG(ERROR) << "[Error] select() error";
			break;
		}

		// A new connection is pending
		if (activity > 0 && FD_ISSET(server_socket, &read_fds)) {
			// 6. Accept the new connection
			client_socket = accept(
			    server_socket, (struct sockaddr *)&client_address,
			    &client_address_length);

			if (client_socket < 0) {
				LOG(ERROR) << "[Error] accept() failed: "
				           << strerror(errno);
			} else {
				LOG(INFO) << "[Info] A client has connected";
				// 7. Create and detach a new thread to handle
				// the client request.
				//    OS will manage the detached thread's
				//    resources
				std::thread(handle_client, client_socket)
				    .detach();
			}
		}
	}

	// Close socket
	LOG(INFO) << "[Info] Server is shutting down. Closing server socket.";
	close(server_socket);
	LOG(INFO) << "[Info] Server has shut down.";

	return 0;
}