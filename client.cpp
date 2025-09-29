#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "include/glog_wrapper.h"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 4468

int main(int argc, char *argv[])
{
	auto glog = GlogWrapper(argv[0]);

	int client_socket;
	struct sockaddr_in server_address;
	char buffer[1024] = {0};

	// Create socket
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0) {
		LOG(ERROR) << "[Error] Failed to create socket";
		return -1;
	}

	// Set server address
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
	server_address.sin_port = htons(SERVER_PORT);

	// Connect to server
	if (connect(client_socket, (struct sockaddr *)&server_address, sizeof
		       (server_address)) < 0) {
		LOG(ERROR) << "[Error] Connection failed";
		return -1;
	}

	LOG(INFO) << "[Info] Connected to server at " << SERVER_ADDRESS << ":"
		<< SERVER_PORT;

	// Receive message
	ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1,
	                              0);
	if (bytes_received > 0) {
		buffer[bytes_received] = '\0';
		LOG(INFO) << "[Info] Message from server: " << buffer;
	} else {
		LOG(ERROR) << "[Error] Failed to receive data";
	}

	close(client_socket);
}