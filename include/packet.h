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
	KEY_EXCHANGE = 1,
	ENCRYPTED_PACKET = 2,

	// Remote command
	AUTH_REQUEST = 10,
	AUTH_RESULT = 11,
	SHELL_EXEC_REQUEST = 12,
	SHELL_EXEC_STDIN = 13,
	SHELL_EXEC_OUTPUT = 14,
	SHELL_EXEC_RESULT = 15,

	// File copy
	FILE_PUT_REQUEST = 20,
	FILE_GET_REQUEST = 21,
	FILE_DATA = 22,
	FILE_RESULT = 23,

	// Session
	DISCONNECT_REQUEST = 30,
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
