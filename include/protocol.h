#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define MAX_PACKET_SIZE (2 * 1024 * 1024)

#include "packet.h"
#include <vector>
#include <string>

/*
 * +------------------+-------------------------------------------------------------+
 * |   Total Length   |                    Packet Data (N bytes)                    |
 * |    (4 bytes)     +-------------------------+-----------------------------------+
 * |                  |     Header (12 bytes)   |         Payload (M bytes)         |
 * +------------------+-------------------------+-----------------------------------+
 * |                  | Magic | Type |Resv|P Len|                                   |
 * |                  | (4B)  | (1B) |(3B)|(4B) |       UTF-8 text or binary        |
 * +------------------+-------+------+----+-----+-----------------------------------+
 */

const uint32_t MAGIC_NUMBER = 0xDBEEAEDF;
const size_t HEADER_SIZE = 12; // Magic(4) + Type(1) + Reserved(3) + PayloadLength(4)

/**
 * @brief Creates the final byte stream to be sent over the network.
 * It builds the header around Packet::content and prepends the total length.
 * @param pkt The Packet object to serialize.
 * @return A vector of bytes ready for sending.
 */
std::vector<char> create_message_stream(const Packet& pkt);

/**
 * @brief Sends exactly n bytes unless the socket errors or closes.
 * @param socket The socket file descriptor.
 * @param data The bytes to send.
 * @param n The byte count to send.
 * @return True if all bytes were sent, false on error.
 */
bool send_all(int socket, const char *data, size_t n);

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

/**
 * @brief Reads and deserializes a complete packet from the socket.
 * @param socket The socket file descriptor to read from.
 * @param pkt A reference to a Packet object to be populated.
 * @return True if a packet was successfully read and parsed, false on any
 * failure (e.g., disconnect, bad magic number, incomplete packet).
 */
bool read_packet(int socket, Packet& pkt);

#endif // PROTOCOL_H_
