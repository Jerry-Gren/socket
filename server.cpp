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
#include <nlohmann/json.hpp>

#include <chrono>
#include <iomanip>
#include <sstream>

#define SERVER_PORT 4468
#define MAX_CLIENT_QUEUE 20

#include "include/glog_wrapper.h"
#include "include/protocol.h"
#include "include/client_info.h"
#include "include/client_manager.h"

using json = nlohmann::json;
// clang-format on

std::atomic<bool> g_server_running(true);
ClientManager g_client_manager;
const std::string g_server_name = "Lab7-SocketServer";

// Signal handler function
// Called when SIGINT (Ctrl+C) or SIGTERM (kill) is received
void signal_handler(int signum)
{
	LOG(INFO) << "[Info] Interrupt signal (" << signum
	          << ") received. Shutting down...";
	g_server_running = false;
}

std::string get_current_time_str()
{
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);

	std::tm timeinfo = *gmtime(&in_time_t);

	std::ostringstream oss;
	oss << std::put_time(&timeinfo, "%Y-%m-%dT%H:%M:%SZ");
	return oss.str();
}

void handle_get_time_request(int client_id)
{
	Packet time_response_pkt;
	time_response_pkt.type = MessageType::GET_TIME_RESPONSE;

	std::string time_str = get_current_time_str();
	time_response_pkt.content = json{{"time", time_str}}.dump();

	g_client_manager.send_to_client(client_id, time_response_pkt);
}

void handle_get_name_request(int client_id)
{
	Packet name_response_pkt;
	name_response_pkt.type = MessageType::GET_NAME_RESPONSE;

	name_response_pkt.content = json{{"name", g_server_name}}.dump();

	g_client_manager.send_to_client(client_id, name_response_pkt);
}

void handle_get_client_list_request(int client_id)
{
	Packet list_response_pkt;
	list_response_pkt.type = MessageType::GET_CLIENT_LIST_RESPONSE;

	json client_list_json = json::array();

	std::vector<ClientInfo> clients = g_client_manager.get_all_clients();

	for (const auto& client : clients) {
		client_list_json.push_back(json{
		    {"id", client.client_id},
		    {"ip", client.ip_address},
		    {"port", client.port}
		});
	}

	list_response_pkt.content = json{
	        {"clients", client_list_json}
	}.dump();

	g_client_manager.send_to_client(client_id, list_response_pkt);
}

void handle_send_message_request(int client_id, const std::string &content)
{
    int target_id;
    std::string message;
    Packet response_pkt;
    response_pkt.type = MessageType::SEND_MESSAGE_RESPONSE;

    try {
        json data = json::parse(content);
        target_id = data.at("target_id").get<int>();
        message = data.at("message").get<std::string>();
    } catch (const json::exception& e) {
        LOG(ERROR) << "[Error] Failed to parse SEND_MESSAGE_REQUEST from client "
                   << client_id << ": " << e.what();
        response_pkt.content = json{
            {"status", "error"},
            {"message", "Bad request format"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
        return;
    }

    if (!g_client_manager.get_client(target_id).has_value()) {
        LOG(WARNING) << "[Warning] Client " << client_id << " tried to send to non-existent client ID "
                     << target_id;
        response_pkt.content = json{
            {"status", "error"},
            {"target_id", target_id},
            {"message", "Client not found"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
        return;
    }

    Packet forward_pkt;
    forward_pkt.type = MessageType::MESSAGE_INDICATION;
    forward_pkt.content = json{
        {"from_id", client_id},
        {"message", message}
    }.dump();

    if (g_client_manager.send_to_client(target_id, forward_pkt)) {
        response_pkt.content = json{
            {"status", "success"},
            {"target_id", target_id}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
    } else {
        response_pkt.content = json{
            {"status", "error"},
            {"target_id", target_id},
            {"message", "Failed to send message"}
        }.dump();
        g_client_manager.send_to_client(client_id, response_pkt);
    }
}

void handle_unhandled_request(int client_id, MessageType type, const std::string &content)
{
	LOG(WARNING) << "[Warning] Unhandled message type from client " << client_id
	    << ": " << MessageTypeToString(type);

	Packet error_pkt;
	error_pkt.type = MessageType::SYSTEM_NOTICE_INDICATION;
	error_pkt.content = json{
	        {"notice", "Error: Unhandled or unknown command."}
	}.dump();
	g_client_manager.send_to_client(client_id, error_pkt);
}

// Client handler function
// This function is executed in a separate thread for each new connection
void handle_client(int client_id, int client_socket)
{

	LOG(INFO) << "[Info] Client Handler started for ID: " << client_id
	          << ", Socket: " << client_socket;

	// Send an initial greeting message
	Packet greeting_pkt;
	greeting_pkt.type = MessageType::SYSTEM_NOTICE_INDICATION;
	greeting_pkt.content =
	    json{{"notice", "Hello from server! Your ID is " + std::to_string(client_id)}}
	        .dump();

	g_client_manager.send_to_client(client_id, greeting_pkt);

	bool client_requested_disconnect = false;

	// Main loop to handle incoming packets
	while (g_server_running && !client_requested_disconnect) {
		Packet received_pkt;
		if (!read_packet(client_socket, received_pkt)) {
			// read_packet returns false on disconnect or critical error
			LOG(INFO) << "[Info] Client " << client_id
			          << " connection closed or errored.";
			break;
		}
		LOG(INFO) << "Received from ID " << client_id
		          << ", Type: " << MessageTypeToString(received_pkt.type)
		          << ", Payload: " << received_pkt.content;

		switch (received_pkt.type) {
		case MessageType::GET_TIME_REQUEST:
			handle_get_time_request(client_id);
			break;
		case MessageType::GET_NAME_REQUEST:
			handle_get_name_request(client_id);
			break;
		case MessageType::GET_CLIENT_LIST_REQUEST:
			handle_get_client_list_request(client_id);
			break;
		case MessageType::SEND_MESSAGE_REQUEST:
			handle_send_message_request(client_id, received_pkt.content);
			break;
		case MessageType::DISCONNECT_REQUEST:
			LOG(INFO)
			    << "[Info] Client " << client_id << " requested disconnect.";
			client_requested_disconnect = true;
			break;
		default:
			handle_unhandled_request(client_id, received_pkt.type,
			                         received_pkt.content);
			break;
		}
	}

	LOG(INFO) << "[Info] Finished handling client ID: " << client_id;
	g_client_manager.remove_client(client_id);
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
	LOG(INFO) << "[Info] Server is listening on port " << SERVER_PORT << "...";

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
		// without blocking
		int activity = select(server_socket + 1, &read_fds, NULL, NULL, &tv);

		// If select() returns an error, but it's not an interrupt from
		// a signal (EINTR), then exit
		if (activity < 0 && errno != EINTR) {
			LOG(ERROR) << "[Error] select() error";
			break;
		}

		// A new connection is pending
		if (activity > 0 && FD_ISSET(server_socket, &read_fds)) {
			// 6. Accept the new connection
			client_socket =
			    accept(server_socket, (struct sockaddr *)&client_address,
			           &client_address_length);

			if (client_socket < 0) {
				LOG(ERROR)
				    << "[Error] accept() failed: " << strerror(errno);
			} else {
				// Get client details for logging and ClientManager
				std::string ip = inet_ntoa(client_address.sin_addr);
				int port = ntohs(client_address.sin_port);

				// 7. Add client to manager and get its ID
				int client_id =
				    g_client_manager.add_client(client_socket, ip, port);

				// 8. Create and detach a new thread to handle the client
				// request.
				std::thread(handle_client, client_id, client_socket)
				    .detach();
			}
		}
	}

	// Close socket
	LOG(INFO) << "[Info] Server is shutting down. Closing server socket";
	/* TODO:
	 * Before closing server_socket, we might want to send a
	 * SERVER_SHUTDOWN_INDICATION to all connected clients.
	 */
	close(server_socket);
	LOG(INFO) << "[Info] Server has shut down";

	return 0;
}