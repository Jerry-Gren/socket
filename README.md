# socket - Custom TCP protocol & chat server

This repository contains an implementation of a custom communication protocol using the TCP Socket API. It demonstrates how to handle packet framing, JSON serialization, and multi-threaded data exchange over a network.

## Reference

- [ZJU Computer Networks Lab 7 Documentation](https://zjucomp.net/docs/Lab7_page)

## Remote Command Mode

Keep one client connected as the command target, then run one-off commands from
another client using an ssh-like shape:

```sh
./client 1 uname -a
printf 'hello' | ./client 1 wc -c
./client -n 1 'uptime; id'
./client --server 192.168.0.10 -p 4468 user@1 'echo "$SHELL"'
```

The destination is the target client ID. `user@ID` is accepted for command-line
compatibility, but the user name is not authenticated or used by this relay
protocol. Remote stdout and stderr are written to the local stdout and stderr,
and the client exits with the remote command exit code.
