#ifndef FILE_TRANSFER_H_
#define FILE_TRANSFER_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

constexpr size_t MAX_FILE_CHUNK_SIZE = 1024 * 1024;

struct FileRequestPayload {
	uint64_t request_id = 0;
	uint64_t total_size = 0;
	std::string path;
};

struct FileDataPayload {
	uint64_t request_id = 0;
	uint64_t total_size = 0;
	uint64_t bytes_sent = 0;
	bool eof = false;
	std::string data;
};

struct FileResultPayload {
	uint64_t request_id = 0;
	bool success = false;
	int32_t code = 1;
	std::string message;
};

inline size_t calculate_file_chunk_size(uint64_t total_size)
{
	if (total_size == 0) {
		return 1;
	}

	size_t one_percent_chunk =
	    static_cast<size_t>((total_size + 99) / 100);
	return std::clamp(one_percent_chunk, static_cast<size_t>(1),
	                  MAX_FILE_CHUNK_SIZE);
}

inline void append_uint32(std::string &out, uint32_t value)
{
	for (int shift = 24; shift >= 0; shift -= 8) {
		out.push_back(static_cast<char>((value >> shift) & 0xff));
	}
}

inline void append_uint64(std::string &out, uint64_t value)
{
	for (int shift = 56; shift >= 0; shift -= 8) {
		out.push_back(static_cast<char>((value >> shift) & 0xff));
	}
}

inline void append_uint8(std::string &out, uint8_t value)
{
	out.push_back(static_cast<char>(value));
}

inline void append_int32(std::string &out, int32_t value)
{
	append_uint32(out, static_cast<uint32_t>(value));
}

inline bool read_uint32(const std::string &input, size_t &offset,
                        uint32_t &value)
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

inline bool read_uint64(const std::string &input, size_t &offset,
                        uint64_t &value)
{
	if (offset + 8 > input.size()) {
		return false;
	}

	value = 0;
	for (int i = 0; i < 8; ++i) {
		value = (value << 8) |
		        static_cast<unsigned char>(input[offset + i]);
	}
	offset += 8;
	return true;
}

inline bool read_uint8(const std::string &input, size_t &offset,
                       uint8_t &value)
{
	if (offset + 1 > input.size()) {
		return false;
	}
	value = static_cast<unsigned char>(input[offset++]);
	return true;
}

inline bool read_int32(const std::string &input, size_t &offset,
                       int32_t &value)
{
	uint32_t raw = 0;
	if (!read_uint32(input, offset, raw)) {
		return false;
	}
	value = static_cast<int32_t>(raw);
	return true;
}

inline void append_string(std::string &out, const std::string &value)
{
	append_uint32(out, static_cast<uint32_t>(value.size()));
	out.append(value);
}

inline bool read_string(const std::string &input, size_t &offset,
                        std::string &value)
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

inline std::string create_file_request_payload(
    uint64_t request_id, uint64_t total_size, const std::string &path)
{
	std::string payload;
	payload.reserve(21 + path.size());
	append_uint8(payload, 1);
	append_uint64(payload, request_id);
	append_uint64(payload, total_size);
	append_string(payload, path);
	return payload;
}

inline bool parse_file_request_payload(const std::string &input,
                                       FileRequestPayload &payload)
{
	size_t offset = 0;
	uint8_t version = 0;
	return read_uint8(input, offset, version) && version == 1 &&
	       read_uint64(input, offset, payload.request_id) &&
	       read_uint64(input, offset, payload.total_size) &&
	       read_string(input, offset, payload.path) &&
	       offset == input.size();
}

inline std::string create_file_data_payload(
    uint64_t request_id, uint64_t total_size, uint64_t bytes_sent, bool eof,
    const std::string &data)
{
	std::string payload;
	payload.reserve(27 + data.size());
	append_uint8(payload, 1);
	append_uint64(payload, request_id);
	append_uint64(payload, total_size);
	append_uint64(payload, bytes_sent);
	append_uint8(payload, eof ? 1 : 0);
	append_string(payload, data);
	return payload;
}

inline bool parse_file_data_payload(const std::string &input,
                                    FileDataPayload &payload)
{
	size_t offset = 0;
	uint8_t version = 0;
	uint8_t eof = 0;
	if (!read_uint8(input, offset, version) || version != 1 ||
	    !read_uint64(input, offset, payload.request_id) ||
	    !read_uint64(input, offset, payload.total_size) ||
	    !read_uint64(input, offset, payload.bytes_sent) ||
	    !read_uint8(input, offset, eof) ||
	    !read_string(input, offset, payload.data) ||
	    offset != input.size() ||
	    (eof != 0 && eof != 1)) {
		return false;
	}
	payload.eof = eof == 1;
	return true;
}

inline std::string create_file_result_payload(
    uint64_t request_id, bool success, int32_t code,
    const std::string &message)
{
	std::string payload;
	payload.reserve(18 + message.size());
	append_uint8(payload, 1);
	append_uint64(payload, request_id);
	append_uint8(payload, success ? 1 : 0);
	append_int32(payload, code);
	append_string(payload, message);
	return payload;
}

inline bool parse_file_result_payload(const std::string &input,
                                      FileResultPayload &payload)
{
	size_t offset = 0;
	uint8_t version = 0;
	uint8_t success = 0;
	if (!read_uint8(input, offset, version) || version != 1 ||
	    !read_uint64(input, offset, payload.request_id) ||
	    !read_uint8(input, offset, success) ||
	    !read_int32(input, offset, payload.code) ||
	    !read_string(input, offset, payload.message) ||
	    offset != input.size() ||
	    (success != 0 && success != 1)) {
		return false;
	}
	payload.success = success == 1;
	return true;
}

#endif // FILE_TRANSFER_H_
