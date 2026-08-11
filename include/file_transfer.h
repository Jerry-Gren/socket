#ifndef FILE_TRANSFER_H_
#define FILE_TRANSFER_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

constexpr size_t MAX_FILE_CHUNK_SIZE = 1024 * 1024;

struct FileTransferPayload {
	uint64_t peer_id = 0; // target_id in requests, from_id in indications
	uint64_t total_size = 0;
	uint64_t bytes_sent = 0;
	bool eof = false;
	std::string filename;
	std::string data;
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

inline std::string create_file_transfer_payload(
    uint64_t peer_id, uint64_t total_size, uint64_t bytes_sent, bool eof,
    const std::string &filename, const std::string &data)
{
	std::string payload;
	payload.reserve(30 + filename.size() + data.size());

	payload.push_back(1); // payload format version
	payload.push_back(eof ? 1 : 0);
	append_uint64(payload, peer_id);
	append_uint64(payload, total_size);
	append_uint64(payload, bytes_sent);
	append_uint32(payload, static_cast<uint32_t>(filename.size()));
	payload.append(filename);
	payload.append(data);

	return payload;
}

inline bool parse_file_transfer_payload(const std::string &input,
                                        FileTransferPayload &payload)
{
	if (input.size() < 30 ||
	    static_cast<unsigned char>(input[0]) != 1) {
		return false;
	}

	size_t offset = 1;
	unsigned char flags = static_cast<unsigned char>(input[offset++]);
	uint32_t filename_size = 0;

	if (!read_uint64(input, offset, payload.peer_id) ||
	    !read_uint64(input, offset, payload.total_size) ||
	    !read_uint64(input, offset, payload.bytes_sent) ||
	    !read_uint32(input, offset, filename_size)) {
		return false;
	}
	if (offset + filename_size > input.size()) {
		return false;
	}

	payload.eof = (flags & 1) != 0;
	payload.filename.assign(input.data() + offset, filename_size);
	offset += filename_size;
	payload.data.assign(input.data() + offset, input.size() - offset);
	return true;
}

#endif // FILE_TRANSFER_H_
