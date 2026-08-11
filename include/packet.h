#ifndef PACKET_H_
#define PACKET_H_

#include <string>
#include <cstdint> // For uint8_t and so on
#include <vector>

/**
 * @enum MessageType
 * @brief Defines all possible message types for our protocol.
 */
enum class MessageType : uint8_t {
	// General
	UNDEFINED = 0,

	// Client to Server Requests
	GET_TIME_REQUEST = 10,
	GET_NAME_REQUEST = 11,
	GET_CLIENT_LIST_REQUEST = 12,
	SEND_MESSAGE_REQUEST = 13,
	SEND_FILE_REQUEST = 14,
	DISCONNECT_REQUEST = 15,

	// Server to Client Responses (synchronous reply to a request)
	GET_TIME_RESPONSE = 20,
	GET_NAME_RESPONSE = 21,
	GET_CLIENT_LIST_RESPONSE = 22,
	SEND_MESSAGE_RESPONSE = 23,
	SEND_FILE_RESPONSE = 24,

	// Server to Client Indications (asynchronous message)
	MESSAGE_INDICATION = 30, // A message from another client
	SERVER_SHUTDOWN_INDICATION = 31, // Server is shutting down
	SYSTEM_NOTICE_INDICATION = 32,
	FILE_INDICATION = 33,
};

/**
 * @struct Packet
 * @brief In-memory representation of our application-level packet.
 */
struct Packet {
	MessageType type = MessageType::UNDEFINED; // Type of packet

	// Content may be UTF-8 JSON for control messages or binary for file data.
	std::string content;
};

#endif // PACKET_H_
