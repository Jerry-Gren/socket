#ifndef SHELL_EXEC_H_
#define SHELL_EXEC_H_

#include <cstdint>
#include <chrono>
#include <functional>
#include <string>

enum class ShellOutputStream : uint8_t {
	STDOUT = 1,
	STDERR = 2,
};

struct ShellExecRequestPayload {
	uint64_t peer_id = 0; // target_id in requests, from_id in forwarded requests
	uint64_t request_id = 0;
	uint32_t timeout_seconds = 30;
	std::string command;
};

struct ShellExecOutputPayload {
	uint64_t peer_id = 0; // target_id in responses, from_id in forwarded responses
	uint64_t request_id = 0;
	ShellOutputStream stream = ShellOutputStream::STDOUT;
	std::string data;
};

struct ShellExecStdinPayload {
	uint64_t peer_id = 0; // target_id in requests, from_id in forwarded input
	uint64_t request_id = 0;
	bool eof = false;
	std::string data;
};

struct ShellExecResultPayload {
	uint64_t peer_id = 0; // target_id in responses, from_id in forwarded responses
	uint64_t request_id = 0;
	int32_t exit_code = -1;
	bool timed_out = false;
	std::string message;
};

using ShellOutputCallback =
    std::function<void(ShellOutputStream stream, const std::string &data)>;

struct ShellInputChunk {
	bool eof = false;
	std::string data;
};

using ShellInputCallback =
    std::function<bool(ShellInputChunk &chunk,
                       std::chrono::milliseconds max_wait)>;

std::string create_shell_exec_request_payload(
    uint64_t peer_id, uint64_t request_id, uint32_t timeout_seconds,
    const std::string &command);
bool parse_shell_exec_request_payload(const std::string &input,
                                      ShellExecRequestPayload &payload);

std::string create_shell_exec_stdin_payload(
    uint64_t peer_id, uint64_t request_id, bool eof,
    const std::string &data);
bool parse_shell_exec_stdin_payload(const std::string &input,
                                    ShellExecStdinPayload &payload);

std::string create_shell_exec_output_payload(
    uint64_t peer_id, uint64_t request_id, ShellOutputStream stream,
    const std::string &data);
bool parse_shell_exec_output_payload(const std::string &input,
                                     ShellExecOutputPayload &payload);

std::string create_shell_exec_result_payload(
    uint64_t peer_id, uint64_t request_id, int32_t exit_code,
    bool timed_out, const std::string &message);
bool parse_shell_exec_result_payload(const std::string &input,
                                     ShellExecResultPayload &payload);

ShellExecResultPayload execute_shell_command(
    const ShellExecRequestPayload &request,
    const ShellOutputCallback &on_output);

ShellExecResultPayload execute_shell_command(
    const ShellExecRequestPayload &request,
    const ShellOutputCallback &on_output,
    const ShellInputCallback &on_input);

#endif // SHELL_EXEC_H_
