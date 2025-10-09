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
	DISCONNECT_REQUEST = 14,

	// Server to Client Responses (synchronous reply to a request)
	GET_TIME_RESPONSE = 20,
	GET_NAME_RESPONSE = 21,
	GET_CLIENT_LIST_RESPONSE = 22,
	SEND_MESSAGE_RESPONSE = 23,

	// Server to Client Indications (asynchronous message)
	MESSAGE_INDICATION = 30, // A message from another client
	SERVER_SHUTDOWN_INDICATION = 31, // Server is shutting down
	SYSTEM_NOTICE_INDICATION = 32
};

/**
 * @struct Packet
 * @brief In-memory representation of our application-level packet.
 * This struct will be serialized into a JSON string to form the payload.
 */
struct Packet {
	MessageType type = MessageType::UNDEFINED; // Type of packet

	// The content is a flexible string, which we will use to store JSON data.
	// We can easily add different fields for different message types.
	// e.g., for SEND_MESSAGE_REQUEST: content = R"({"target_id": 123, "message": "Hello"})"
	// e.g., for GET_TIME_RESPONSE: content = R"({"time": "2025-10-06 15:30:00 JST"})"
	std::string content; // Content of packet (payload)
};

#endif // PACKET_H_