#ifndef PACKET_H_
#define PACKET_H_

#include <string>
#include <cstdint> // For uint8_t and so on

/**
 * @enum MessageType
 * @brief Defines the different types of packets that can be sent or received.
 *
 * Using 'enum class' provides type safety (e.g., you can't accidentally compare it to an int).
 * Specifying the underlying type as uint8_t controls its size, which is useful for serialization.
 */
enum class MessageType : uint8_t {
	UNDEFINED,      // undefined or error
	CHAT_TEXT,      // normal chat message from user
	SYSTEM_NOTICE,  // system notice from server (e.g. "User A joined")
	USER_LOGIN      // login request
	// ... TODO: Add more MessageType in future
    };

/**
 * @struct Packet
 * @brief Represents a structured data packet for network communication.
 *
 * This struct organizes message data, separating metadata (like the type)
 * from the actual payload (the content).
 */
struct Packet {
	MessageType type = MessageType::UNDEFINED; // Type of packet
	std::string content;                      // Content of packet (payload)

	// TODO: Add more Packet fields in future
	// uint32_t sender_id;
	// uint64_t timestamp;
	// ...
};

#endif // PACKET_H_