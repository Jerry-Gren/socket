#ifndef CLIENT_INFO_H_
#define CLIENT_INFO_H_

#include <string>

/**
 * @struct ClientInfo
 * @brief Holds all relevant information for a single connected client.
 */
struct ClientInfo {
	uint64_t client_id;
	int socket_fd;
	std::string ip_address;
	int port;
};

#endif // CLIENT_INFO_H_