#include "include/shell_exec.h"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr unsigned char SHELL_PAYLOAD_VERSION = 1;
constexpr size_t SHELL_OUTPUT_CHUNK_SIZE = 32 * 1024;
constexpr size_t SHELL_STDIN_CHUNK_SIZE = 32 * 1024;

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

void append_int32(std::string &out, int32_t value)
{
	append_uint32(out, static_cast<uint32_t>(value));
}

void append_uint64(std::string &out, uint64_t value)
{
	for (int shift = 56; shift >= 0; shift -= 8) {
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

bool read_int32(const std::string &input, size_t &offset, int32_t &value)
{
	uint32_t raw = 0;
	if (!read_uint32(input, offset, raw)) {
		return false;
	}
	value = static_cast<int32_t>(raw);
	return true;
}

bool read_uint64(const std::string &input, size_t &offset, uint64_t &value)
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

bool read_string(const std::string &input, size_t &offset, std::string &value)
{
	uint32_t size = 0;
	if (!read_uint32(input, offset, size) || offset + size > input.size()) {
		return false;
	}
	value.assign(input.data() + offset, size);
	offset += size;
	return true;
}

void append_string(std::string &out, const std::string &value)
{
	append_uint32(out, static_cast<uint32_t>(value.size()));
	out.append(value);
}

bool is_valid_version(const std::string &input, size_t &offset)
{
	uint8_t version = 0;
	return read_uint8(input, offset, version) &&
	       version == SHELL_PAYLOAD_VERSION;
}

bool set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::string describe_signal(int signal_number)
{
	std::ostringstream oss;
	oss << "terminated by signal " << signal_number;
	return oss.str();
}

bool drain_fd(int fd, ShellOutputStream stream,
              const ShellOutputCallback &on_output)
{
	char buffer[SHELL_OUTPUT_CHUNK_SIZE];
	bool open = true;
	while (true) {
		ssize_t count = read(fd, buffer, sizeof(buffer));
		if (count > 0) {
			on_output(stream, std::string(buffer, count));
			continue;
		}
		if (count == 0) {
			open = false;
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			break;
		}
		open = false;
		break;
	}
	return open;
}

bool write_pending_stdin(int fd, std::string &pending_input,
                         size_t &pending_offset)
{
	while (pending_offset < pending_input.size()) {
		const char *next = pending_input.data() + pending_offset;
		size_t remaining = pending_input.size() - pending_offset;
		size_t count = std::min(remaining, SHELL_STDIN_CHUNK_SIZE);
		ssize_t written = write(fd, next, count);
		if (written > 0) {
			pending_offset += static_cast<size_t>(written);
			continue;
		}
		if (written < 0 && errno == EINTR) {
			continue;
		}
		if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return true;
		}
		return false;
	}
	pending_input.clear();
	pending_offset = 0;
	return true;
}

} // namespace

std::string create_shell_exec_request_payload(
    uint64_t peer_id, uint64_t request_id, uint32_t timeout_seconds,
    const std::string &command)
{
	std::string payload;
	payload.reserve(25 + command.size());
	append_uint8(payload, SHELL_PAYLOAD_VERSION);
	append_uint64(payload, peer_id);
	append_uint64(payload, request_id);
	append_uint32(payload, timeout_seconds);
	append_string(payload, command);
	return payload;
}

bool parse_shell_exec_request_payload(const std::string &input,
                                      ShellExecRequestPayload &payload)
{
	size_t offset = 0;
	return is_valid_version(input, offset) &&
	       read_uint64(input, offset, payload.peer_id) &&
	       read_uint64(input, offset, payload.request_id) &&
	       read_uint32(input, offset, payload.timeout_seconds) &&
	       read_string(input, offset, payload.command) &&
	       offset == input.size();
}

std::string create_shell_exec_stdin_payload(
    uint64_t peer_id, uint64_t request_id, bool eof,
    const std::string &data)
{
	std::string payload;
	payload.reserve(22 + data.size());
	append_uint8(payload, SHELL_PAYLOAD_VERSION);
	append_uint64(payload, peer_id);
	append_uint64(payload, request_id);
	append_uint8(payload, eof ? 1 : 0);
	append_string(payload, data);
	return payload;
}

bool parse_shell_exec_stdin_payload(const std::string &input,
                                    ShellExecStdinPayload &payload)
{
	size_t offset = 0;
	uint8_t eof = 0;
	if (!is_valid_version(input, offset) ||
	    !read_uint64(input, offset, payload.peer_id) ||
	    !read_uint64(input, offset, payload.request_id) ||
	    !read_uint8(input, offset, eof) ||
	    !read_string(input, offset, payload.data) ||
	    offset != input.size() ||
	    (eof != 0 && eof != 1)) {
		return false;
	}
	payload.eof = eof == 1;
	return true;
}

std::string create_shell_exec_output_payload(
    uint64_t peer_id, uint64_t request_id, ShellOutputStream stream,
    const std::string &data)
{
	std::string payload;
	payload.reserve(22 + data.size());
	append_uint8(payload, SHELL_PAYLOAD_VERSION);
	append_uint64(payload, peer_id);
	append_uint64(payload, request_id);
	append_uint8(payload, static_cast<uint8_t>(stream));
	append_string(payload, data);
	return payload;
}

bool parse_shell_exec_output_payload(const std::string &input,
                                     ShellExecOutputPayload &payload)
{
	size_t offset = 0;
	uint8_t stream = 0;
	if (!is_valid_version(input, offset) ||
	    !read_uint64(input, offset, payload.peer_id) ||
	    !read_uint64(input, offset, payload.request_id) ||
	    !read_uint8(input, offset, stream) ||
	    !read_string(input, offset, payload.data) ||
	    offset != input.size()) {
		return false;
	}
	if (stream != static_cast<uint8_t>(ShellOutputStream::STDOUT) &&
	    stream != static_cast<uint8_t>(ShellOutputStream::STDERR)) {
		return false;
	}
	payload.stream = static_cast<ShellOutputStream>(stream);
	return true;
}

std::string create_shell_exec_result_payload(
    uint64_t peer_id, uint64_t request_id, int32_t exit_code,
    bool timed_out, const std::string &message)
{
	std::string payload;
	payload.reserve(27 + message.size());
	append_uint8(payload, SHELL_PAYLOAD_VERSION);
	append_uint64(payload, peer_id);
	append_uint64(payload, request_id);
	append_int32(payload, exit_code);
	append_uint8(payload, timed_out ? 1 : 0);
	append_string(payload, message);
	return payload;
}

bool parse_shell_exec_result_payload(const std::string &input,
                                     ShellExecResultPayload &payload)
{
	size_t offset = 0;
	uint8_t timed_out = 0;
	if (!is_valid_version(input, offset) ||
	    !read_uint64(input, offset, payload.peer_id) ||
	    !read_uint64(input, offset, payload.request_id) ||
	    !read_int32(input, offset, payload.exit_code) ||
	    !read_uint8(input, offset, timed_out) ||
	    !read_string(input, offset, payload.message) ||
	    offset != input.size() ||
	    (timed_out != 0 && timed_out != 1)) {
		return false;
	}
	payload.timed_out = timed_out == 1;
	return true;
}

ShellExecResultPayload execute_shell_command(
    const ShellExecRequestPayload &request,
    const ShellOutputCallback &on_output)
{
	auto close_stdin = [](ShellInputChunk &chunk,
	                      std::chrono::milliseconds) {
		chunk.eof = true;
		chunk.data.clear();
		return true;
	};
	return execute_shell_command(request, on_output, close_stdin);
}

ShellExecResultPayload execute_shell_command(
    const ShellExecRequestPayload &request,
    const ShellOutputCallback &on_output,
    const ShellInputCallback &on_input)
{
	ShellExecResultPayload result;
	result.peer_id = request.peer_id;
	result.request_id = request.request_id;

	int stdin_pipe[2] = {-1, -1};
	int stdout_pipe[2] = {-1, -1};
	int stderr_pipe[2] = {-1, -1};
	if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0 ||
	    pipe(stderr_pipe) != 0) {
		if (stdin_pipe[0] >= 0) close(stdin_pipe[0]);
		if (stdin_pipe[1] >= 0) close(stdin_pipe[1]);
		if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
		if (stdout_pipe[1] >= 0) close(stdout_pipe[1]);
		if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
		if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
		result.message = "failed to create command pipes";
		return result;
	}

	pid_t pid = fork();
	if (pid < 0) {
		close(stdin_pipe[0]);
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		result.message = "failed to fork process";
		return result;
	}

	if (pid == 0) {
		setpgid(0, 0);
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);
		close(stderr_pipe[0]);
		dup2(stdin_pipe[0], STDIN_FILENO);
		dup2(stdout_pipe[1], STDOUT_FILENO);
		dup2(stderr_pipe[1], STDERR_FILENO);
		close(stdin_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);
		execl("/bin/sh", "sh", "-lc", request.command.c_str(),
		      static_cast<char *>(nullptr));
		_exit(127);
	}

	setpgid(pid, pid);
	close(stdin_pipe[0]);
	close(stdout_pipe[1]);
	close(stderr_pipe[1]);
	set_nonblocking(stdin_pipe[1]);
	set_nonblocking(stdout_pipe[0]);
	set_nonblocking(stderr_pipe[0]);

	auto started_at = std::chrono::steady_clock::now();
	bool stdout_open = true;
	bool stderr_open = true;
	bool stdin_open = true;
	bool stdin_eof = false;
	std::string pending_input;
	size_t pending_input_offset = 0;
	bool child_exited = false;
	int child_status = 0;

	while (stdout_open || stderr_open || !child_exited) {
		if (!child_exited) {
			pid_t waited = waitpid(pid, &child_status, WNOHANG);
			if (waited == pid) {
				child_exited = true;
			}
		}

		auto now = std::chrono::steady_clock::now();
		if (!child_exited && request.timeout_seconds > 0 &&
		    now - started_at >
		        std::chrono::seconds(request.timeout_seconds)) {
			kill(-pid, SIGKILL);
			waitpid(pid, &child_status, 0);
			child_exited = true;
			result.timed_out = true;
			result.exit_code = -1;
			result.message = "command timed out";
		}

		if (stdin_open && pending_input.empty() && !stdin_eof &&
		    !child_exited) {
			ShellInputChunk input_chunk;
			if (on_input(input_chunk, std::chrono::milliseconds(0))) {
				if (!input_chunk.data.empty()) {
					pending_input = std::move(input_chunk.data);
					pending_input_offset = 0;
				}
				if (input_chunk.eof) {
					stdin_eof = true;
				}
			}
		}

		if (stdin_open && !pending_input.empty()) {
			stdin_open = write_pending_stdin(stdin_pipe[1], pending_input,
			                                 pending_input_offset);
		}
		if (stdin_open && pending_input.empty() && stdin_eof) {
			close(stdin_pipe[1]);
			stdin_pipe[1] = -1;
			stdin_open = false;
		}

		struct pollfd fds[3];
		nfds_t nfds = 0;
		if (stdout_open) {
			fds[nfds++] = {stdout_pipe[0], POLLIN | POLLHUP | POLLERR, 0};
		}
		if (stderr_open) {
			fds[nfds++] = {stderr_pipe[0], POLLIN | POLLHUP | POLLERR, 0};
		}
		if (stdin_open && !pending_input.empty()) {
			fds[nfds++] = {stdin_pipe[1], POLLOUT | POLLHUP | POLLERR, 0};
		}

		if (nfds > 0) {
			int poll_result = poll(fds, nfds, 50);
			if (poll_result < 0 && errno != EINTR) {
				break;
			}
		} else if (stdin_open && !stdin_eof && !child_exited) {
			ShellInputChunk input_chunk;
			if (on_input(input_chunk, std::chrono::milliseconds(50))) {
				if (!input_chunk.data.empty()) {
					pending_input = std::move(input_chunk.data);
					pending_input_offset = 0;
				}
				if (input_chunk.eof) {
					stdin_eof = true;
				}
			}
		}

		if (stdout_open) {
			stdout_open = drain_fd(stdout_pipe[0], ShellOutputStream::STDOUT,
			                       on_output);
		}
		if (stderr_open) {
			stderr_open = drain_fd(stderr_pipe[0], ShellOutputStream::STDERR,
			                       on_output);
		}

		if (child_exited && !stdout_open && !stderr_open) {
			break;
		}
	}

	close(stdout_pipe[0]);
	close(stderr_pipe[0]);
	if (stdin_pipe[1] >= 0) {
		close(stdin_pipe[1]);
	}

	if (!result.timed_out) {
		if (WIFEXITED(child_status)) {
			result.exit_code = WEXITSTATUS(child_status);
			result.message = "completed";
		} else if (WIFSIGNALED(child_status)) {
			result.exit_code = -1;
			result.message = describe_signal(WTERMSIG(child_status));
		} else {
			result.exit_code = -1;
			result.message = "process ended without exit status";
		}
	}
	return result;
}
