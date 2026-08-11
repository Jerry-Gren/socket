#include "include/identity.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
std::string g_config_dir;

std::string trim(const std::string &value)
{
	size_t first = 0;
	while (first < value.size() &&
	       std::isspace(static_cast<unsigned char>(value[first]))) {
		++first;
	}
	size_t last = value.size();
	while (last > first &&
	       std::isspace(static_cast<unsigned char>(value[last - 1]))) {
		--last;
	}
	return value.substr(first, last - first);
}

std::string host_pattern(const std::string &host, int port)
{
	return host + ":" + std::to_string(port);
}

bool extract_public_key(EVP_PKEY *key, std::string &public_key)
{
	public_key.assign(ED25519_PUBLIC_KEY_SIZE, '\0');
	size_t len = public_key.size();
	if (EVP_PKEY_get_raw_public_key(
	        key, reinterpret_cast<unsigned char *>(public_key.data()),
	        &len) <= 0 ||
	    len != ED25519_PUBLIC_KEY_SIZE) {
		return false;
	}
	return true;
}

bool extract_private_key(EVP_PKEY *key, std::string &private_key)
{
	private_key.assign(ED25519_PRIVATE_KEY_SIZE, '\0');
	size_t len = private_key.size();
	if (EVP_PKEY_get_raw_private_key(
	        key, reinterpret_cast<unsigned char *>(private_key.data()),
	        &len) <= 0 ||
	    len != ED25519_PRIVATE_KEY_SIZE) {
		return false;
	}
	return true;
}

bool read_key_file(const std::string &path, std::string &private_key,
                   std::string &error)
{
	std::ifstream input(path);
	if (!input.is_open()) {
		error = "failed to open key file: " + path;
		return false;
	}

	std::string type;
	std::string private_hex;
	input >> type >> private_hex;
	if (type != "ed25519" || !hex_decode(private_hex, private_key) ||
	    private_key.size() != ED25519_PRIVATE_KEY_SIZE) {
		error = "invalid Ed25519 key file: " + path;
		return false;
	}
	return true;
}

} // namespace

std::string default_config_dir()
{
	if (!g_config_dir.empty()) {
		return g_config_dir;
	}
	return "xsh-data";
}

void set_default_config_dir(const std::string &path)
{
	g_config_dir = path;
}

std::string default_user_key_path()
{
	return (fs::path(default_config_dir()) / "id_ed25519").string();
}

std::string default_known_hosts_path()
{
	return (fs::path(default_config_dir()) / "known_hosts").string();
}

std::string default_host_key_path()
{
	return (fs::path(default_config_dir()) / "xshd_host_ed25519").string();
}

std::string default_authorized_keys_path()
{
	return (fs::path(default_config_dir()) / "authorized_keys").string();
}

std::string default_username()
{
	if (const char *user = std::getenv("USER")) {
		if (*user != '\0') {
			return user;
		}
	}
	if (const char *logname = std::getenv("LOGNAME")) {
		if (*logname != '\0') {
			return logname;
		}
	}
	return "user";
}

std::string hex_encode(const std::string &input)
{
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');
	for (unsigned char ch : input) {
		oss << std::setw(2) << static_cast<int>(ch);
	}
	return oss.str();
}

bool hex_decode(const std::string &input, std::string &output)
{
	if (input.size() % 2 != 0) {
		return false;
	}
	output.clear();
	output.reserve(input.size() / 2);
	for (size_t i = 0; i < input.size(); i += 2) {
		char hi = input[i];
		char lo = input[i + 1];
		if (!std::isxdigit(static_cast<unsigned char>(hi)) ||
		    !std::isxdigit(static_cast<unsigned char>(lo))) {
			return false;
		}
		unsigned int value = 0;
		std::istringstream iss(input.substr(i, 2));
		iss >> std::hex >> value;
		output.push_back(static_cast<char>(value));
	}
	return true;
}

std::string fingerprint_sha256(const std::string &data)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char *>(data.data()),
	       data.size(), digest);
	return hex_encode(std::string(reinterpret_cast<char *>(digest),
	                              SHA256_DIGEST_LENGTH));
}

bool ensure_parent_directory(const std::string &path)
{
	std::error_code ec;
	fs::path parent = fs::path(path).parent_path();
	if (parent.empty()) {
		return true;
	}
	fs::create_directories(parent, ec);
	return !ec;
}

bool generate_ed25519_key(IdentityKey &identity, std::string &error)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
	    EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
	    EVP_PKEY_CTX_free);
	if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
		error = "failed to initialize Ed25519 key generation";
		return false;
	}

	EVP_PKEY *raw_key = nullptr;
	if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0) {
		error = "failed to generate Ed25519 key";
		return false;
	}
	identity.key.reset(raw_key);
	if (!extract_public_key(identity.key.get(), identity.public_key)) {
		error = "failed to extract Ed25519 public key";
		return false;
	}
	return true;
}

bool save_ed25519_private_key(const std::string &path, EVP_PKEY *key,
                              std::string &error)
{
	std::string private_key;
	std::string public_key;
	if (!extract_private_key(key, private_key)) {
		error = "failed to extract Ed25519 private key";
		return false;
	}
	if (!extract_public_key(key, public_key)) {
		error = "failed to extract Ed25519 public key";
		return false;
	}
	if (!ensure_parent_directory(path)) {
		error = "failed to create key directory";
		return false;
	}

	std::ofstream output(path, std::ios::trunc);
	if (!output.is_open()) {
		error = "failed to write key file: " + path;
		return false;
	}
	output << "ed25519 " << hex_encode(private_key) << "\n";
	output.close();
	chmod(path.c_str(), S_IRUSR | S_IWUSR);

	std::ofstream public_output(path + ".pub", std::ios::trunc);
	if (public_output.is_open()) {
		public_output << "ed25519 " << hex_encode(public_key) << "\n";
	}
	return true;
}

bool load_ed25519_private_key(const std::string &path, IdentityKey &identity,
                              std::string &error)
{
	std::string private_key;
	if (!read_key_file(path, private_key, error)) {
		return false;
	}

	EVP_PKEY *raw_key = EVP_PKEY_new_raw_private_key(
	    EVP_PKEY_ED25519, nullptr,
	    reinterpret_cast<const unsigned char *>(private_key.data()),
	    private_key.size());
	if (!raw_key) {
		error = "failed to parse Ed25519 private key";
		return false;
	}
	identity.key.reset(raw_key);
	if (!extract_public_key(identity.key.get(), identity.public_key)) {
		error = "failed to extract Ed25519 public key";
		return false;
	}
	return true;
}

bool load_or_create_ed25519_key(const std::string &path, IdentityKey &identity,
                                std::string &error)
{
	if (fs::exists(path)) {
		return load_ed25519_private_key(path, identity, error);
	}
	if (!generate_ed25519_key(identity, error)) {
		return false;
	}
	return save_ed25519_private_key(path, identity.key.get(), error);
}

bool sign_ed25519(EVP_PKEY *key, const std::string &message,
                  std::string &signature)
{
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
	    EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr,
	                               key) <= 0) {
		return false;
	}
	size_t sig_len = 0;
	if (EVP_DigestSign(ctx.get(), nullptr, &sig_len,
	                   reinterpret_cast<const unsigned char *>(message.data()),
	                   message.size()) <= 0) {
		return false;
	}
	signature.assign(sig_len, '\0');
	return EVP_DigestSign(
	           ctx.get(), reinterpret_cast<unsigned char *>(signature.data()),
	           &sig_len,
	           reinterpret_cast<const unsigned char *>(message.data()),
	           message.size()) > 0 &&
	       (signature.resize(sig_len), true);
}

bool verify_ed25519(const std::string &public_key,
                    const std::string &message,
                    const std::string &signature)
{
	if (public_key.size() != ED25519_PUBLIC_KEY_SIZE) {
		return false;
	}
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
	    EVP_PKEY_new_raw_public_key(
	        EVP_PKEY_ED25519, nullptr,
	        reinterpret_cast<const unsigned char *>(public_key.data()),
	        public_key.size()),
	    EVP_PKEY_free);
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
	    EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!key || !ctx ||
	    EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr,
	                         key.get()) <= 0) {
		return false;
	}
	return EVP_DigestVerify(
	           ctx.get(),
	           reinterpret_cast<const unsigned char *>(signature.data()),
	           signature.size(),
	           reinterpret_cast<const unsigned char *>(message.data()),
	           message.size()) == 1;
}

bool verify_or_record_host_key(const std::string &known_hosts_path,
                               const std::string &host, int port,
                               const std::string &host_public_key,
                               std::string &error)
{
	std::string pattern = host_pattern(host, port);
	std::ifstream input(known_hosts_path);
	std::string line;
	while (std::getline(input, line)) {
		line = trim(line);
		if (line.empty() || line[0] == '#') {
			continue;
		}
		std::istringstream iss(line);
		std::string stored_pattern;
		std::string type;
		std::string key_hex;
		iss >> stored_pattern >> type >> key_hex;
		if (stored_pattern != pattern) {
			continue;
		}
		std::string stored_key;
		if (type != "ed25519" || !hex_decode(key_hex, stored_key)) {
			error = "invalid known_hosts entry for " + pattern;
			return false;
		}
		if (stored_key != host_public_key) {
			error = "host key mismatch for " + pattern +
			        "; expected SHA256:" + fingerprint_sha256(stored_key) +
			        ", got SHA256:" + fingerprint_sha256(host_public_key);
			return false;
		}
		return true;
	}

	if (!ensure_parent_directory(known_hosts_path)) {
		error = "failed to create known_hosts directory";
		return false;
	}
	std::ofstream output(known_hosts_path, std::ios::app);
	if (!output.is_open()) {
		error = "failed to write known_hosts";
		return false;
	}
	output << pattern << " ed25519 " << hex_encode(host_public_key)
	       << "\n";
	output.close();
	chmod(known_hosts_path.c_str(), S_IRUSR | S_IWUSR);
	std::cerr << "host-key: recorded " << pattern
	          << " SHA256:" << fingerprint_sha256(host_public_key) << "\n";
	return true;
}

bool is_authorized_user_key(const std::string &authorized_keys_path,
                            const std::string &username,
                            const std::string &public_key,
                            std::string &error)
{
	std::ifstream input(authorized_keys_path);
	if (!input.is_open()) {
		error = "authorized_keys not found: " + authorized_keys_path;
		return false;
	}

	std::string line;
	while (std::getline(input, line)) {
		line = trim(line);
		if (line.empty() || line[0] == '#') {
			continue;
		}
		std::istringstream iss(line);
		std::string user;
		std::string type;
		std::string key_hex;
		iss >> user >> type >> key_hex;
		std::string stored_key;
		if (user == username && type == "ed25519" &&
		    hex_decode(key_hex, stored_key) &&
		    stored_key == public_key) {
			return true;
		}
	}

	error = "public key is not authorized for user " + username;
	return false;
}
