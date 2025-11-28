#ifndef UTILITY_H_
#define UTILITY_H_

#include <string>

/**
 * @brief Sanitizes a string to prevent terminal injection.
 * It replaces the ESC character ('\x1b') with a harmless, readable tag "[ESC]".
 *
 * @param input The raw string to sanitize.
 * @return The sanitized string.
 */
inline std::string sanitize_for_terminal(std::string input) {
	size_t pos = input.find('\x1b');
	while (pos != std::string::npos) {
		// Replace \x1b with "[ESC]" so it's visible but harmless
		input.replace(pos, 1, "[ESC]");
		// Search for the next one, starting *after* the tag we just inserted
		// +5 to skip "[ESC]"
		pos = input.find('\x1b', pos + 5);
	}
	return input;
}

static const std::string base64_chars =
	     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	     "abcdefghijklmnopqrstuvwxyz"
	     "0123456789+/";

inline std::string base64_encode(const std::vector<char>& data) {
	std::string ret;
	int i = 0, j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	for (unsigned char c : data) {
		char_array_3[i++] = c;
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;
			for(i = 0; (i <4) ; i++) ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}
	if (i) {
		for(j = i; j < 3; j++) char_array_3[j] = '\0';
		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;
		for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];
		while((i++ < 3)) ret += '=';
	}
	return ret;
}

inline std::vector<char> base64_decode(const std::string& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0, j = 0, in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::vector<char> ret;

	while (in_len-- && ( encoded_string[in_] != '=') &&
	       (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i ==4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
			for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
			i = 0;
		}
	       }
	if (i) {
		for (j = i; j <4; j++) char_array_4[j] = 0;
		for (j = 0; j <4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
		for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
	}
	return ret;
}

#endif // UTILITY_H_