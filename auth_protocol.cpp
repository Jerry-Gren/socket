#include "include/auth_protocol.h"

namespace {

constexpr unsigned char AUTH_PAYLOAD_VERSION = 1;

void append_uint8(std::string &out, uint8_t value)
{
	out.push_back(static_cast<char>(value));
}

void append_uint32(std::string &out, uint32_t value)
{
	for (int shift = 24; shift >= 0; shift -= 8) {
		out.push_back(static_cast<char>((value >> shift) & 0xff));
	}
}

bool read_uint8(const std::string &input, size_t &offset, uint8_t &value)
{
	if (offset + 1 > input.size()) {
		return false;
	}
	value = static_cast<unsigned char>(input[offset++]);
	return true;
}

bool read_uint32(const std::string &input, size_t &offset, uint32_t &value)
{
	if (offset + 4 > input.size()) {
		return false;
	}
	value = 0;
	for (int i = 0; i < 4; ++i) {
		value = (value << 8) |
		        static_cast<unsigned char>(input[offset + i]);
	}
	offset += 4;
	return true;
}

void append_string(std::string &out, const std::string &value)
{
	append_uint32(out, static_cast<uint32_t>(value.size()));
	out.append(value);
}

bool read_string(const std::string &input, size_t &offset, std::string &value)
{
	uint32_t size = 0;
	if (!read_uint32(input, offset, size) ||
	    offset + size > input.size()) {
		return false;
	}
	value.assign(input.data() + offset, size);
	offset += size;
	return true;
}

} // namespace

std::string create_user_auth_message(const std::string &session_id,
                                     const std::string &username,
                                     const std::string &public_key)
{
	std::string message = "xsh-user-auth-v1";
	append_string(message, session_id);
	append_string(message, username);
	append_string(message, public_key);
	return message;
}

std::string create_auth_request_payload(const std::string &username,
                                        const std::string &public_key,
                                        const std::string &signature)
{
	std::string payload;
	payload.reserve(13 + username.size() + public_key.size() +
	                signature.size());
	append_uint8(payload, AUTH_PAYLOAD_VERSION);
	append_string(payload, username);
	append_string(payload, public_key);
	append_string(payload, signature);
	return payload;
}

bool parse_auth_request_payload(const std::string &input,
                                AuthRequestPayload &payload)
{
	size_t offset = 0;
	uint8_t version = 0;
	return read_uint8(input, offset, version) &&
	       version == AUTH_PAYLOAD_VERSION &&
	       read_string(input, offset, payload.username) &&
	       read_string(input, offset, payload.public_key) &&
	       read_string(input, offset, payload.signature) &&
	       offset == input.size();
}

std::string create_auth_result_payload(bool success,
                                       const std::string &message)
{
	std::string payload;
	payload.reserve(6 + message.size());
	append_uint8(payload, AUTH_PAYLOAD_VERSION);
	append_uint8(payload, success ? 1 : 0);
	append_string(payload, message);
	return payload;
}

bool parse_auth_result_payload(const std::string &input,
                               AuthResultPayload &payload)
{
	size_t offset = 0;
	uint8_t version = 0;
	uint8_t success = 0;
	if (!read_uint8(input, offset, version) ||
	    version != AUTH_PAYLOAD_VERSION ||
	    !read_uint8(input, offset, success) ||
	    !read_string(input, offset, payload.message) ||
	    offset != input.size() ||
	    (success != 0 && success != 1)) {
		return false;
	}
	payload.success = success == 1;
	return true;
}
