# socket - Custom TCP protocol & chat server

This repository contains an implementation of a custom communication protocol using the TCP Socket API. It demonstrates how to handle packet framing, JSON serialization, and multi-threaded data exchange over a network.

## Reference

- [ZJU Computer Networks Lab 7 Documentation](https://zjucomp.net/docs/Lab7_page)

## Remote Command Mode

Run `server` on the controlled host, then run one-off commands from another
machine using an ssh-like shape. The controlled host does not need a separate
long-running `client` process:

```sh
./client 192.168.0.107 uname -a
printf 'hello' | ./client 192.168.0.107 wc -c
./client -n user@192.168.0.107 'uptime; id'
./client -p 4468 localhost 'echo "$SHELL"'
```

The destination is the server host or `user@server_host`. The user name is
accepted for command-line compatibility, but it is not authenticated or used by
this protocol yet. Remote stdout and stderr are written to the local stdout and
stderr, and the client exits with the remote command exit code.

The older relay mode is still available when a command must run on a connected
client behind the server:

```sh
./client --server relay.example.net --target-client 3 uname -a
```
