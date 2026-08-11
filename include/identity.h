#ifndef IDENTITY_H_
#define IDENTITY_H_

#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <string>

struct IdentityKey {
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key;
	std::string public_key;

	IdentityKey() : key(nullptr, EVP_PKEY_free) {}
};

std::string default_config_dir();
void set_default_config_dir(const std::string &path);
std::string default_user_key_path();
std::string default_known_hosts_path();
std::string default_host_key_path();
std::string default_authorized_keys_path();
std::string default_username();

std::string hex_encode(const std::string &input);
bool hex_decode(const std::string &input, std::string &output);
std::string fingerprint_sha256(const std::string &data);

bool ensure_parent_directory(const std::string &path);
bool load_or_create_ed25519_key(const std::string &path, IdentityKey &identity,
                                std::string &error);
bool load_ed25519_private_key(const std::string &path, IdentityKey &identity,
                              std::string &error);
bool save_ed25519_private_key(const std::string &path, EVP_PKEY *key,
                              std::string &error);
bool generate_ed25519_key(IdentityKey &identity, std::string &error);

bool sign_ed25519(EVP_PKEY *key, const std::string &message,
                  std::string &signature);
bool verify_ed25519(const std::string &public_key,
                    const std::string &message,
                    const std::string &signature);

bool verify_or_record_host_key(const std::string &known_hosts_path,
                               const std::string &host, int port,
                               const std::string &host_public_key,
                               std::string &error);
bool is_authorized_user_key(const std::string &authorized_keys_path,
                            const std::string &username,
                            const std::string &public_key,
                            std::string &error);

#endif // IDENTITY_H_
