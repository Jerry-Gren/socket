#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include "packet.h"
#include <vector>
#include <string>

/*
 * +------------------+-------------------------------------------------------------+
 * |   Total Length   |                    Packet Data (N bytes)                    |
 * |    (4 bytes)     +-------------------------+-----------------------------------+
 * |                  |     Header (12 bytes)   |         Payload (M bytes)         |
 * +------------------+-------------------------+-----------------------------------+
 *                    | Magic | Type |Resv|P Len|                                   |
 *                    | (4B)  | (1B) |(3B)|(4B) |           (JSON String)           |
 * +------------------+-------+------+----+-----+-----------------------------------+
 */

const uint32_t MAGIC_NUMBER = 0xDEADBEEF;
const size_t HEADER_SIZE = 12; // Magic(4) + Type(1) + Reserved(3) + PayloadLength(4)

/**
 * @brief Creates the final byte stream to be sent over the network.
 * It serializes the Packet content to JSON, builds the header, and prepends the total length.
 * @param pkt The Packet object to serialize.
 * @return A vector of bytes ready for sending.
 */
std::vector<char> create_message_stream(const Packet& pkt);

/**
 * @brief A helper function to read exactly n bytes from a socket.
 * @param socket The socket file descriptor.
 * @param n The number of bytes to read.
 * @param buffer The buffer to store the read data.
 * @return True on success, false on failure.
 */
bool read_n_bytes(int socket, size_t n, std::vector<char>& buffer);

/**
 * @brief Converts a MessageType enum to a human-readable string.
 * @param type The MessageType enum value.
 * @return A constant character pointer to the string representation.
 */
const char* MessageTypeToString(MessageType type);

#endif // PROTOCOL_H_
