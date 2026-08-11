#ifndef SECURE_CHANNEL_H_
#define SECURE_CHANNEL_H_

#include "packet.h"
#include <array>
#include <cstdint>

struct SecureSession {
	std::array<unsigned char, 32> send_key{};
	std::array<unsigned char, 32> recv_key{};
	uint64_t send_seq = 0;
	uint64_t recv_seq = 0;
	bool ready = false;
};

bool perform_client_handshake(int socket, SecureSession &session);
bool perform_server_handshake(int socket, SecureSession &session);

bool send_secure_packet(int socket, SecureSession &session, const Packet &pkt);
bool read_secure_packet(int socket, SecureSession &session, Packet &pkt);

#endif // SECURE_CHANNEL_H_
