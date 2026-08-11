# socket - xsh/xcp remote tools

This branch packages the encrypted TCP transport as focused command-line tools:

- `xshd`: controlled-host daemon
- `xsh`: ssh-like one-off remote command execution
- `xcp`: scp-like file copy

All application traffic runs inside the encrypted channel.

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

## Remote Commands

Run the daemon on the controlled host:

```sh
./build/xshd
```

Run commands from another machine:

```sh
./build/xsh 192.168.0.107 uname -a
./build/xsh user@192.168.0.107 'uptime; id'
printf 'hello' | ./build/xsh 192.168.0.107 wc -c
./build/xsh -p 4468 localhost 'echo "$SHELL"'
```

`xsh` writes remote stdout and stderr to local stdout and stderr, and exits with
the remote command exit code.

## File Copy

Upload a local file:

```sh
./build/xcp ./local.bin user@192.168.0.107:/tmp/local.bin
```

Download a remote file:

```sh
./build/xcp user@192.168.0.107:/tmp/remote.bin ./remote.bin
```

`xcp` prints transfer progress and ETA to stderr.

## Reference

- [ZJU Computer Networks Lab 7 Documentation](https://zjucomp.net/docs/Lab7_page)
