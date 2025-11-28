#include "include/protocol.h"
#include <nlohmann/json.hpp>
#include <arpa/inet.h>      // For htonl, ntohl
#include <vector>
#include <map>
#include <glog/logging.h>

using json = nlohmann::json;

std::vector<char> create_message_stream(const Packet &pkt)
{
	// 1. Serialize the Packet's content to a JSON string
	std::string payload_str = pkt.content; // For now, we assume content is already a valid JSON string or simple text.
	uint32_t payload_len = payload_str.length();

	// 2. Build the fixed-size header
	std::vector<char> header(HEADER_SIZE);
	uint32_t magic = htonl(MAGIC_NUMBER);
	uint8_t type = static_cast<uint8_t>(pkt.type);
	uint32_t payload_len_n = htonl(payload_len);

	memcpy(header.data(), &magic, sizeof(magic));
	memcpy(header.data() + 4, &type, sizeof(type));
	// Bytes 5, 6, 7 are reserved and remain 0
	memcpy(header.data() + 8, &payload_len_n, sizeof(payload_len_n));

	// 3. Construct the final message stream: [Total Length, 4 bytes][Header][Payload]
	uint32_t total_len = HEADER_SIZE + payload_len;
	uint32_t total_len_n = htonl(total_len);

	std::vector<char> message_stream;
	message_stream.resize(4 + total_len); // Allocate space for the full message

	memcpy(message_stream.data(), &total_len_n, sizeof(total_len_n));
	memcpy(message_stream.data() + 4, header.data(), HEADER_SIZE);
	memcpy(message_stream.data() + 4 + HEADER_SIZE, payload_str.data(), payload_len);

	return message_stream;
}

bool read_n_bytes(int socket, size_t n, std::vector<char>& buffer)
{
	buffer.resize(n);
	size_t bytes_read = 0;
	while (bytes_read < n) {
		ssize_t result = recv(socket, buffer.data() + bytes_read, n - bytes_read, 0);
		if (result <= 0) {
			// Error or connection closed
			return false;
		}
		bytes_read += result;
	}
	return true;
}

bool read_packet(int socket, Packet& pkt)
{
	std::vector<char> length_buffer;
	// 1. Read the 4-byte total length prefix
	if (!read_n_bytes(socket, 4, length_buffer)) {
		// Failed to read, likely a disconnect
		return false;
	}
	uint32_t total_len = ntohl(*reinterpret_cast<uint32_t*>(length_buffer.data()));

	if (total_len > MAX_PACKET_SIZE) {
		LOG(ERROR) << "[Error] Packet size " << total_len
			   << " exceeds max limit of " << MAX_PACKET_SIZE
			   << ". Kicking client.";
		return false;
	}
	if (total_len < HEADER_SIZE) {
		LOG(ERROR) << "[Error] Packet size " << total_len
			   << " is smaller than header. Kicking client.";
		return false;
	}

	// 2. Read the rest of the packet data (Header + Payload)
	std::vector<char> packet_data_buffer;
	if (!read_n_bytes(socket, total_len, packet_data_buffer)) {
		LOG(ERROR) << "[Error] Failed to read packet data.";
		return false;
	}

	// 3. Parse the header and deserialize the payload
	uint32_t magic = ntohl(*reinterpret_cast<uint32_t*>(packet_data_buffer.data()));
	if (magic != MAGIC_NUMBER) {
		LOG(ERROR) << "[Error] Invalid magic number.";
		return false;
	}

	// Populate the output packet
	pkt.type = static_cast<MessageType>(packet_data_buffer[4]);

	uint32_t payload_len = ntohl(*reinterpret_cast<uint32_t*>(packet_data_buffer.data() + 8));
	if (payload_len > 0) {
		pkt.content.assign(packet_data_buffer.data() + HEADER_SIZE, payload_len);
	} else {
		pkt.content.clear();
	}

	// Successfully parsed
	return true;
}

const char* MessageTypeToString(MessageType type) {
	// Using a map for easy lookup.
	// Note: A switch statement would be slightly more performant, but a map is more concise.
	static const std::map<MessageType, const char*> type_map = {
		{MessageType::UNDEFINED, "UNDEFINED"},
		{MessageType::GET_TIME_REQUEST, "GET_TIME_REQUEST"},
		{MessageType::GET_NAME_REQUEST, "GET_NAME_REQUEST"},
		{MessageType::GET_CLIENT_LIST_REQUEST, "GET_CLIENT_LIST_REQUEST"},
		{MessageType::SEND_MESSAGE_REQUEST, "SEND_MESSAGE_REQUEST"},
		{MessageType::SEND_FILE_REQUEST, "SEND_FILE_REQUEST"},
		{MessageType::DISCONNECT_REQUEST, "DISCONNECT_REQUEST"},
		{MessageType::GET_TIME_RESPONSE, "GET_TIME_RESPONSE"},
		{MessageType::GET_NAME_RESPONSE, "GET_NAME_RESPONSE"},
		{MessageType::GET_CLIENT_LIST_RESPONSE, "GET_CLIENT_LIST_RESPONSE"},
		{MessageType::SEND_MESSAGE_RESPONSE, "SEND_MESSAGE_RESPONSE"},
		{MessageType::SEND_FILE_RESPONSE, "SEND_FILE_RESPONSE"},
		{MessageType::MESSAGE_INDICATION, "MESSAGE_INDICATION"},
		{MessageType::SERVER_SHUTDOWN_INDICATION, "SERVER_SHUTDOWN_INDICATION"},
		{MessageType::SYSTEM_NOTICE_INDICATION, "SYSTEM_NOTICE_INDICATION"},
		{MessageType::FILE_INDICATION, "FILE_INDICATION"},
	};

	auto it = type_map.find(type);
	if (it != type_map.end()) {
		return it->second;
	}
	return "UNKNOWN_TYPE";
}