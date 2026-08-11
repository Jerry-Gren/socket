#ifndef AUTH_PROTOCOL_H_
#define AUTH_PROTOCOL_H_

#include <cstdint>
#include <string>

struct AuthRequestPayload {
	std::string username;
	std::string public_key;
	std::string signature;
};

struct AuthResultPayload {
	bool success = false;
	std::string message;
};

std::string create_user_auth_message(const std::string &session_id,
                                     const std::string &username,
                                     const std::string &public_key);

std::string create_auth_request_payload(const std::string &username,
                                        const std::string &public_key,
                                        const std::string &signature);
bool parse_auth_request_payload(const std::string &input,
                                AuthRequestPayload &payload);

std::string create_auth_result_payload(bool success,
                                       const std::string &message);
bool parse_auth_result_payload(const std::string &input,
                               AuthResultPayload &payload);

#endif // AUTH_PROTOCOL_H_
