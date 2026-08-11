#include "include/secure_channel.h"
#include "include/protocol.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr size_t X25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_TAG_SIZE = 16;
constexpr size_t AES_GCM_NONCE_SIZE = 12;
constexpr unsigned char SECURE_PACKET_VERSION = 1;
constexpr unsigned char HOST_AUTH_VERSION = 2;

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpCipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void append_uint32(std::string &out, uint32_t value)
{
	for (int shift = 24; shift >= 0; shift -= 8) {
		out.push_back(static_cast<char>((value >> shift) & 0xff));
	}
}

void append_uint64(std::string &out, uint64_t value)
{
	for (int shift = 56; shift >= 0; shift -= 8) {
		out.push_back(static_cast<char>((value >> shift) & 0xff));
	}
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

void append_string(std::string &out, const std::string &value)
{
	append_uint32(out, static_cast<uint32_t>(value.size()));
	out.append(value);
}

std::string sha256_bytes(const std::string &data)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char *>(data.data()),
	       data.size(), digest);
	return std::string(reinterpret_cast<char *>(digest),
	                   SHA256_DIGEST_LENGTH);
}

std::string create_host_auth_message(
    const std::string &client_public_key,
    const std::string &server_public_key,
    const std::string &host_public_key)
{
	std::string message = "xsh-host-auth-v1";
	append_string(message, client_public_key);
	append_string(message, server_public_key);
	append_string(message, host_public_key);
	return message;
}

bool generate_x25519_key(EvpPkeyPtr &key, std::string &public_key)
{
	EvpPkeyCtxPtr keygen_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr),
	                         EVP_PKEY_CTX_free);
	if (!keygen_ctx || EVP_PKEY_keygen_init(keygen_ctx.get()) <= 0) {
		return false;
	}

	EVP_PKEY *raw_key = nullptr;
	if (EVP_PKEY_keygen(keygen_ctx.get(), &raw_key) <= 0) {
		return false;
	}
	key.reset(raw_key);

	public_key.resize(X25519_PUBLIC_KEY_SIZE);
	size_t public_key_len = public_key.size();
	if (EVP_PKEY_get_raw_public_key(
	        key.get(), reinterpret_cast<unsigned char *>(public_key.data()),
	        &public_key_len) <= 0 ||
	    public_key_len != X25519_PUBLIC_KEY_SIZE) {
		return false;
	}
	return true;
}

bool derive_shared_secret(EVP_PKEY *local_key, const std::string &peer_public_key,
                          std::string &shared_secret)
{
	if (peer_public_key.size() != X25519_PUBLIC_KEY_SIZE) {
		return false;
	}

	EvpPkeyPtr peer_key(
	    EVP_PKEY_new_raw_public_key(
	        EVP_PKEY_X25519, nullptr,
	        reinterpret_cast<const unsigned char *>(peer_public_key.data()),
	        peer_public_key.size()),
	    EVP_PKEY_free);
	if (!peer_key) {
		return false;
	}

	EvpPkeyCtxPtr derive_ctx(EVP_PKEY_CTX_new(local_key, nullptr),
	                         EVP_PKEY_CTX_free);
	if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx.get()) <= 0 ||
	    EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_key.get()) <= 0) {
		return false;
	}

	size_t secret_len = 0;
	if (EVP_PKEY_derive(derive_ctx.get(), nullptr, &secret_len) <= 0) {
		return false;
	}
	shared_secret.resize(secret_len);
	if (EVP_PKEY_derive(
	        derive_ctx.get(),
	        reinterpret_cast<unsigned char *>(shared_secret.data()),
	        &secret_len) <= 0) {
		return false;
	}
	shared_secret.resize(secret_len);
	return true;
}

bool hkdf_sha256(const std::string &secret, const std::string &salt,
                 const std::string &info,
                 std::array<unsigned char, AES_256_KEY_SIZE> &out_key)
{
	EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
	if (!kdf) {
		return false;
	}
	std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf_ptr(kdf,
	                                                          EVP_KDF_free);
	std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> kdf_ctx(
	    EVP_KDF_CTX_new(kdf), EVP_KDF_CTX_free);
	if (!kdf_ctx) {
		return false;
	}

	OSSL_PARAM params[] = {
	    OSSL_PARAM_construct_utf8_string("digest",
	                                     const_cast<char *>("SHA256"), 0),
	    OSSL_PARAM_construct_octet_string(
	        "key", const_cast<char *>(secret.data()), secret.size()),
	    OSSL_PARAM_construct_octet_string(
	        "salt", const_cast<char *>(salt.data()), salt.size()),
	    OSSL_PARAM_construct_octet_string(
	        "info", const_cast<char *>(info.data()), info.size()),
	    OSSL_PARAM_construct_end()};

	return EVP_KDF_derive(kdf_ctx.get(), out_key.data(), out_key.size(),
	                      params) > 0;
}

void make_nonce(uint64_t seq,
                std::array<unsigned char, AES_GCM_NONCE_SIZE> &nonce)
{
	nonce.fill(0);
	for (int i = 0; i < 8; ++i) {
		nonce[4 + i] =
		    static_cast<unsigned char>((seq >> (56 - (i * 8))) & 0xff);
	}
}

std::string serialize_plain_packet(const Packet &pkt)
{
	std::string plain;
	plain.reserve(5 + pkt.content.size());
	plain.push_back(static_cast<char>(pkt.type));
	append_uint32(plain, static_cast<uint32_t>(pkt.content.size()));
	plain.append(pkt.content);
	return plain;
}

bool parse_plain_packet(const std::string &plain, Packet &pkt)
{
	if (plain.size() < 5) {
		return false;
	}

	size_t offset = 0;
	pkt.type = static_cast<MessageType>(
	    static_cast<unsigned char>(plain[offset++]));

	uint32_t content_size = 0;
	if (!read_uint32(plain, offset, content_size) ||
	    offset + content_size != plain.size()) {
		return false;
	}
	pkt.content.assign(plain.data() + offset, content_size);
	return true;
}

bool aes_gcm_encrypt(
    const std::array<unsigned char, AES_256_KEY_SIZE> &key, uint64_t seq,
    const std::string &plain, std::string &encrypted_payload)
{
	std::array<unsigned char, AES_GCM_NONCE_SIZE> nonce;
	make_nonce(seq, nonce);

	EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx ||
	    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
	                       nullptr) <= 0 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
	                        nullptr) <= 0 ||
	    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
	                       nonce.data()) <= 0) {
		return false;
	}

	std::string aad = "xsh-secure-channel-v1";
	append_uint64(aad, seq);
	int len = 0;
	if (EVP_EncryptUpdate(
	        ctx.get(), nullptr, &len,
	        reinterpret_cast<const unsigned char *>(aad.data()),
	        aad.size()) <= 0) {
		return false;
	}

	std::string ciphertext(plain.size(), '\0');
	int ciphertext_len = 0;
	if (!plain.empty() &&
	    EVP_EncryptUpdate(
	        ctx.get(), reinterpret_cast<unsigned char *>(ciphertext.data()),
	        &len, reinterpret_cast<const unsigned char *>(plain.data()),
	        plain.size()) <= 0) {
		return false;
	}
	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(
	        ctx.get(),
	        reinterpret_cast<unsigned char *>(ciphertext.data()) + len,
	        &len) <= 0) {
		return false;
	}
	ciphertext_len += len;
	ciphertext.resize(ciphertext_len);

	std::array<unsigned char, AES_GCM_TAG_SIZE> tag{};
	if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(),
	                        tag.data()) <= 0) {
		return false;
	}

	encrypted_payload.reserve(1 + ciphertext.size() + tag.size());
	encrypted_payload.push_back(static_cast<char>(SECURE_PACKET_VERSION));
	encrypted_payload.append(ciphertext);
	encrypted_payload.append(reinterpret_cast<const char *>(tag.data()),
	                         tag.size());
	return true;
}

bool aes_gcm_decrypt(
    const std::array<unsigned char, AES_256_KEY_SIZE> &key, uint64_t seq,
    const std::string &encrypted_payload, std::string &plain)
{
	if (encrypted_payload.size() < 1 + AES_GCM_TAG_SIZE ||
	    static_cast<unsigned char>(encrypted_payload[0]) !=
	        SECURE_PACKET_VERSION) {
		return false;
	}

	size_t ciphertext_size = encrypted_payload.size() - 1 - AES_GCM_TAG_SIZE;
	const char *ciphertext = encrypted_payload.data() + 1;
	const char *tag = encrypted_payload.data() + 1 + ciphertext_size;

	std::array<unsigned char, AES_GCM_NONCE_SIZE> nonce;
	make_nonce(seq, nonce);

	EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx ||
	    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
	                       nullptr) <= 0 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
	                        nullptr) <= 0 ||
	    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
	                       nonce.data()) <= 0) {
		return false;
	}

	std::string aad = "xsh-secure-channel-v1";
	append_uint64(aad, seq);
	int len = 0;
	if (EVP_DecryptUpdate(
	        ctx.get(), nullptr, &len,
	        reinterpret_cast<const unsigned char *>(aad.data()),
	        aad.size()) <= 0) {
		return false;
	}

	plain.assign(ciphertext_size, '\0');
	int plain_len = 0;
	if (ciphertext_size > 0 &&
	    EVP_DecryptUpdate(
	        ctx.get(), reinterpret_cast<unsigned char *>(plain.data()), &len,
	        reinterpret_cast<const unsigned char *>(ciphertext),
	        ciphertext_size) <= 0) {
		return false;
	}
	plain_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
	                        AES_GCM_TAG_SIZE, const_cast<char *>(tag)) <= 0 ||
	    EVP_DecryptFinal_ex(
	        ctx.get(), reinterpret_cast<unsigned char *>(plain.data()) + len,
	        &len) <= 0) {
		return false;
	}
	plain_len += len;
	plain.resize(plain_len);
	return true;
}

bool send_raw_packet(int socket, const Packet &pkt)
{
	std::vector<char> message_stream = create_message_stream(pkt);
	return send_all(socket, message_stream.data(), message_stream.size());
}

bool receive_key_exchange(int socket, std::string &peer_public_key)
{
	Packet pkt;
	if (!read_packet(socket, pkt) || pkt.type != MessageType::KEY_EXCHANGE ||
	    pkt.content.size() != X25519_PUBLIC_KEY_SIZE) {
		return false;
	}
	peer_public_key = pkt.content;
	return true;
}

bool send_client_key_exchange(int socket, const std::string &public_key)
{
	Packet pkt;
	pkt.type = MessageType::KEY_EXCHANGE;
	pkt.content = public_key;
	return send_raw_packet(socket, pkt);
}

bool send_server_key_exchange(int socket, const std::string &server_public_key,
                              const std::string &host_public_key,
                              const std::string &signature)
{
	Packet pkt;
	pkt.type = MessageType::KEY_EXCHANGE;
	pkt.content.reserve(1 + server_public_key.size() +
	                    host_public_key.size() + 4 + signature.size());
	pkt.content.push_back(static_cast<char>(HOST_AUTH_VERSION));
	pkt.content.append(server_public_key);
	pkt.content.append(host_public_key);
	append_string(pkt.content, signature);
	return send_raw_packet(socket, pkt);
}

bool receive_server_key_exchange(int socket, std::string &server_public_key,
                                 std::string &host_public_key,
                                 std::string &signature)
{
	Packet pkt;
	if (!read_packet(socket, pkt) || pkt.type != MessageType::KEY_EXCHANGE ||
	    pkt.content.size() < 1 + X25519_PUBLIC_KEY_SIZE +
	                             ED25519_PUBLIC_KEY_SIZE + 4 ||
	    static_cast<unsigned char>(pkt.content[0]) != HOST_AUTH_VERSION) {
		return false;
	}
	size_t offset = 1;
	server_public_key.assign(pkt.content.data() + offset,
	                         X25519_PUBLIC_KEY_SIZE);
	offset += X25519_PUBLIC_KEY_SIZE;
	host_public_key.assign(pkt.content.data() + offset,
	                       ED25519_PUBLIC_KEY_SIZE);
	offset += ED25519_PUBLIC_KEY_SIZE;
	return read_string(pkt.content, offset, signature) &&
	       offset == pkt.content.size();
}

bool finish_handshake(const std::string &shared_secret,
                      const std::string &client_public_key,
                      const std::string &server_public_key, bool is_client,
                      SecureSession &session)
{
	std::string salt = client_public_key + server_public_key;
	std::array<unsigned char, AES_256_KEY_SIZE> client_to_server{};
	std::array<unsigned char, AES_256_KEY_SIZE> server_to_client{};

	if (!hkdf_sha256(shared_secret, salt,
	                 "xsh client-to-xshd v1",
	                 client_to_server) ||
	    !hkdf_sha256(shared_secret, salt,
	                 "xsh xshd-to-client v1",
	                 server_to_client)) {
		return false;
	}

	if (is_client) {
		session.send_key = client_to_server;
		session.recv_key = server_to_client;
	} else {
		session.send_key = server_to_client;
		session.recv_key = client_to_server;
	}
	session.send_seq = 0;
	session.recv_seq = 0;
	session.session_id =
	    sha256_bytes("xsh-session-v1" + client_public_key +
	                 server_public_key + shared_secret);
	session.ready = true;
	return true;
}

} // namespace

bool perform_client_handshake(int socket, SecureSession &session,
                              const std::string &host, int port,
                              const std::string &known_hosts_path,
                              std::string &error)
{
	EvpPkeyPtr local_key(nullptr, EVP_PKEY_free);
	std::string client_public_key;
	if (!generate_x25519_key(local_key, client_public_key) ||
	    !send_client_key_exchange(socket, client_public_key)) {
		error = "failed to send key exchange";
		return false;
	}

	std::string server_public_key;
	std::string host_public_key;
	std::string host_signature;
	if (!receive_server_key_exchange(socket, server_public_key,
	                                 host_public_key, host_signature)) {
		error = "failed to receive host-authenticated key exchange";
		return false;
	}

	std::string host_message = create_host_auth_message(
	    client_public_key, server_public_key, host_public_key);
	if (!verify_ed25519(host_public_key, host_message, host_signature)) {
		error = "invalid xshd host key signature";
		return false;
	}
	if (!verify_or_record_host_key(known_hosts_path, host, port,
	                               host_public_key, error)) {
		return false;
	}

	std::string shared_secret;
	if (!derive_shared_secret(local_key.get(), server_public_key,
	                          shared_secret)) {
		error = "failed to derive shared secret";
		return false;
	}
	if (!finish_handshake(shared_secret, client_public_key,
	                      server_public_key, true, session)) {
		error = "failed to derive channel keys";
		return false;
	}
	session.peer_host_public_key = host_public_key;
	return true;
}

bool perform_server_handshake(int socket, SecureSession &session,
                              IdentityKey &host_identity,
                              std::string &error)
{
	std::string client_public_key;
	if (!receive_key_exchange(socket, client_public_key)) {
		error = "failed to receive client key exchange";
		return false;
	}

	EvpPkeyPtr local_key(nullptr, EVP_PKEY_free);
	std::string server_public_key;
	if (!generate_x25519_key(local_key, server_public_key)) {
		error = "failed to generate x25519 key";
		return false;
	}

	std::string host_message = create_host_auth_message(
	    client_public_key, server_public_key, host_identity.public_key);
	std::string host_signature;
	if (!sign_ed25519(host_identity.key.get(), host_message,
	                  host_signature) ||
	    !send_server_key_exchange(socket, server_public_key,
	                              host_identity.public_key,
	                              host_signature)) {
		error = "failed to send host-authenticated key exchange";
		return false;
	}

	std::string shared_secret;
	if (!derive_shared_secret(local_key.get(), client_public_key,
	                          shared_secret)) {
		error = "failed to derive shared secret";
		return false;
	}
	if (!finish_handshake(shared_secret, client_public_key,
	                      server_public_key, false, session)) {
		error = "failed to derive channel keys";
		return false;
	}
	session.peer_host_public_key = host_identity.public_key;
	return true;
}

bool send_secure_packet(int socket, SecureSession &session, const Packet &pkt)
{
	if (!session.ready) {
		return false;
	}

	std::string plain = serialize_plain_packet(pkt);
	std::string encrypted_payload;
	if (!aes_gcm_encrypt(session.send_key, session.send_seq, plain,
	                     encrypted_payload)) {
		return false;
	}

	Packet encrypted_pkt;
	encrypted_pkt.type = MessageType::ENCRYPTED_PACKET;
	encrypted_pkt.content = encrypted_payload;
	if (!send_raw_packet(socket, encrypted_pkt)) {
		return false;
	}
	++session.send_seq;
	return true;
}

bool read_secure_packet(int socket, SecureSession &session, Packet &pkt)
{
	if (!session.ready) {
		return false;
	}

	Packet encrypted_pkt;
	if (!read_packet(socket, encrypted_pkt) ||
	    encrypted_pkt.type != MessageType::ENCRYPTED_PACKET) {
		return false;
	}

	std::string plain;
	if (!aes_gcm_decrypt(session.recv_key, session.recv_seq,
	                     encrypted_pkt.content, plain) ||
	    !parse_plain_packet(plain, pkt)) {
		return false;
	}
	++session.recv_seq;
	return true;
}
