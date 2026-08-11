#ifndef UTILITY_H_
#define UTILITY_H_

#include <string>
#include <filesystem>

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

inline std::string executable_dir(const char *program)
{
	std::error_code ec;
	std::filesystem::path path(program ? program : ".");
	if (!path.is_absolute()) {
		path = std::filesystem::absolute(path, ec);
		if (ec) {
			return ".";
		}
	}
	path = std::filesystem::weakly_canonical(path, ec);
	if (ec) {
		path = std::filesystem::absolute(program ? program : ".", ec);
	}
	return path.parent_path().string();
}

inline std::string path_under_executable_dir(const char *program,
                                             const std::string &relative)
{
	return (std::filesystem::path(executable_dir(program)) / relative).string();
}

#endif // UTILITY_H_
