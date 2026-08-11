#ifndef SECURE_CHANNEL_H_
#define SECURE_CHANNEL_H_

#include "packet.h"
#include "identity.h"
#include <array>
#include <cstdint>
#include <string>

struct SecureSession {
	std::array<unsigned char, 32> send_key{};
	std::array<unsigned char, 32> recv_key{};
	std::string session_id;
	std::string peer_host_public_key;
	uint64_t send_seq = 0;
	uint64_t recv_seq = 0;
	bool ready = false;
};

bool perform_client_handshake(int socket, SecureSession &session,
                              const std::string &host, int port,
                              const std::string &known_hosts_path,
                              std::string &error);
bool perform_server_handshake(int socket, SecureSession &session,
                              IdentityKey &host_identity,
                              std::string &error);

bool send_secure_packet(int socket, SecureSession &session, const Packet &pkt);
bool read_secure_packet(int socket, SecureSession &session, Packet &pkt);

#endif // SECURE_CHANNEL_H_
