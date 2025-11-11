// include/client_manager.h
#ifndef CLIENT_MANAGER_H_
#define CLIENT_MANAGER_H_

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <atomic>
#include <optional>
#include "client_info.h"
#include "protocol.h"       // For Packet
#include <arpa/inet.h>      // For htonl, ntohl
#include <unistd.h>         // For close
#include <glog/logging.h>

/**
 * @class ClientManager
 * @brief A thread-safe class to manage all connected clients.
 *
 * This class handles adding, removing, and finding clients, as well as
 * sending messages to specific clients.
 */
class ClientManager {
public:
    ClientManager() : next_client_id_(1) {} // Start IDs from 1

    /**
     * @brief Adds a new client to the manager.
     * @param socket_fd The new client's socket file descriptor.
     * @param ip_address The new client's IP address.
     * @param port The new client's port.
     * @return The unique client_id assigned to this client.
     */
    int add_client(int socket_fd, const std::string& ip_address, int port) {
        int client_id = next_client_id_.fetch_add(1);

        ClientInfo new_client;
        new_client.client_id = client_id;
        new_client.socket_fd = socket_fd;
        new_client.ip_address = ip_address;
        new_client.port = port;

        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_[client_id] = new_client;

        LOG(INFO) << "[ClientManager] Client " << client_id << " (FD: "
                  << socket_fd << ", IP: " << ip_address << ":" << port
                  << ") connected.";
        return client_id;
    }

    /**
     * @brief Removes a client from the manager by their ID.
     * Also closes the client's socket.
     * @param client_id The ID of the client to remove.
     */
    void remove_client(int client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex_);

        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            // Close the socket when removing the client
            close(it->second.socket_fd);
            LOG(INFO) << "[ClientManager] Client " << client_id
                      << " (FD: " << it->second.socket_fd << ") disconnected.";
            clients_.erase(it);
        } else {
            LOG(WARNING) << "[ClientManager] Attempted to remove non-existent client ID: "
                         << client_id;
        }
    }

    /**
     * @brief Gets information for a single client.
     * @param client_id The ID of the client to find.
     * @return An std::optional<ClientInfo> containing the client's info if
     * found, otherwise std::nullopt.
     */
    std::optional<ClientInfo> get_client(int client_id) {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * @brief Gets a list of all currently connected clients.
     * @return A std::vector containing the ClientInfo for all clients.
     */
    std::vector<ClientInfo> get_all_clients() {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        std::vector<ClientInfo> client_list;
        for (const auto& pair : clients_) {
            client_list.push_back(pair.second);
        }
        return client_list;
    }

    /**
     * @brief Sends a packet to a specific client.
     * @param client_id The ID of the target client.
     * @param pkt The Packet to send.
     * @return True if send was successful (or at least attempted), false if
     * client was not found.
     */
    bool send_to_client(int client_id, const Packet& pkt) {
        std::optional<ClientInfo> client = get_client(client_id);
        if (!client) {
            LOG(WARNING) << "[ClientManager] Failed to send: Client ID "
                         << client_id << " not found.";
            return false;
        }

        std::vector<char> message_stream = create_message_stream(pkt);

        // Note: This send operation is blocking and is done while holding
        // no locks on the manager, which is good.
        if (send(client->socket_fd, message_stream.data(), message_stream.size(), 0) < 0) {
            LOG(ERROR) << "[ClientManager] Failed to send message to Client ID "
                       << client_id << " (FD: " << client->socket_fd << ")";
            // We might want to trigger a removal here, but for now we'll let
            // the client's own handler thread detect the disconnect.
            return false;
        }
        return true;
    }

private:
    std::map<int, ClientInfo> clients_; // Map from client_id to ClientInfo
    std::mutex clients_mutex_;           // Mutex to protect the clients_ map
    std::atomic<uint64_t> next_client_id_;  // Atomic counter for unique client IDs
};

#endif // CLIENT_MANAGER_H_