# socket - Custom TCP protocol & chat server

This repository contains an implementation of a custom communication protocol using the TCP Socket API. It demonstrates how to handle packet framing, JSON serialization, and multi-threaded data exchange over a network.

## Prerequisites

Before building, ensure you have the following installed:
* **C++ Compiler**: GCC (7.0+) or Clang supporting C++17.
* **CMake**: Version 3.10 or higher.
* **Google Glog**: Logging library.
* **nlohmann/json**: JSON library for C++.

## How to Build

1. Create a subdir for storing build files and enter it:

   ```shell
   $ mkdir build
   $ cd build
   ```

2. Generate `Makefile` using CMake:

   ```shell
   $ cmake ..
   ```

3. Build the project with all available CPU cores:

   ```shell
   $ make -j$(nproc)
   ```

4. Check if both `client` and `server` exist in this build folder.

## Usage

1. **Start the Server**

   **Note:** The server must be started **before** any clients.

   ```shell
   $ ./server
   ```

2. **Start the Client**

   You can run the client in two modes:

   **Option A: Connect to Localhost (Default)**

   ```shell
   $ ./client
   ```

   **Option B: Connect to a Specific Server IP**

   ```shell
   $ ./client <SERVER_IP>
   # Example: ./client 192.168.1.50
   ```

3. **Commands**

   Once connected, input commands into the terminal:

   * `help`: Show available commands.
   * `list`: Show all online client IDs.
   * `send`: Send a message to a specific client ID.
   * `time` / `name`: Request server information.
   * `disconnect`: Close the connection.

## Reference

- [ZJU Computer Networks Lab 7 Documentation](https://zjucomp.net/docs/Lab7_page)
