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

#endif // UTILITY_H_