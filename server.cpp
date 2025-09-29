#include <iostream>
#include <string>
#include <cstring>    // For memset
#include <unistd.h>    // For close
#include <sys/socket.h>    // For socket functions
#include <netinet/in.h>    // For sockaddr_in

#define SERVER_PORT 4468

#include "include/glog_wrapper.h"

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

	int server_socket, client_socket;
	struct sockaddr_in server_address, client_address;
	socklen_t client_address_length = sizeof(client_address);
	const char *greeting_message = "Hello from server!";

	// Create socket
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		LOG(ERROR) << "Failed to create socket";
		return -1;
	}

	// Set server address
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(SERVER_PORT);

	// Bind socket to local address
	if (bind(server_socket, (struct sockaddr *)&server_address,
	         sizeof(server_address)) < 0) {
		LOG(ERROR) << "[Error] Binding failed";
		return -1;
	}

	// Listen to connection from client
	if (listen(server_socket, 1) < 0) {
		LOG(ERROR) << "[Error] Listening failed";
		return -1;
	}
	LOG(INFO) << "[Info] Server is listening on port " << SERVER_PORT <<
		"...";

	// Accept connection from client
	client_socket = accept(server_socket,
	                       (struct sockaddr *)&client_address,
	                       &client_address_length);
	if (client_socket < 0) {
		LOG(INFO) << "[Error] Accepting connection failed";
		return -1;
	}

	LOG(INFO) << "[Info] Connected to client!";
	// Send greeting message to client
	send(client_socket, greeting_message, strlen(greeting_message), 0);

	// Close socket
	close(client_socket);
	close(server_socket);

	return 0;
}