# socket - xsh/xcp remote tools

This branch packages the encrypted TCP transport as focused command-line tools:

- `xshd`: controlled-host daemon
- `xsh`: ssh-like one-off remote command execution
- `xcp`: scp-like file copy

All application traffic runs inside the encrypted channel. `xshd` has a
persistent Ed25519 host key, and `xsh`/`xcp` verify it through a
known-hosts file. Users authenticate with Ed25519 public keys listed in
`authorized_keys`.

Runtime state is stored beside the executable, not in the user's home
directory:

- `<exe-dir>/logs/`
- `<exe-dir>/xsh-data/known_hosts`
- `<exe-dir>/xsh-data/id_ed25519`
- `<exe-dir>/xsh-data/xshd_host_ed25519`
- `<exe-dir>/xsh-data/authorized_keys`

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

On first start, `xshd` creates its host key at
`./build/xsh-data/xshd_host_ed25519`. On first client use, `xsh` creates a user
key at `./build/xsh-data/id_ed25519` and prints its public key if it is not
authorized yet. Add that public key to the controlled host's
`./build/xsh-data/authorized_keys`:

```text
username ed25519 <hex-public-key>
```

Run commands from another machine:

```sh
./build/xsh 192.168.0.107 uname -a
./build/xsh user@192.168.0.107 'uptime; id'
printf 'hello' | ./build/xsh 192.168.0.107 wc -c
./build/xsh -p 4468 localhost 'echo "$SHELL"'
```

`xsh` writes remote stdout and stderr to local stdout and stderr, and exits with
the remote command exit code. The first successful host-key observation is
recorded in `<exe-dir>/xsh-data/known_hosts`; later host-key changes are
rejected.

The `user@host` user is authenticated and authorized against `authorized_keys`.
Commands currently run as the OS user that started `xshd`.

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
Paths follow scp-like file semantics:

- `local -> user@host:path` uploads a local file.
- `user@host:path -> local` downloads a remote file.
- Remote absolute paths are used as-is.
- Remote `~` and `~/...` expand on the host running `xshd`.
- Remote relative paths are resolved by the `xshd` process.
- Local paths are resolved by the local `xcp` process.
- If the destination is an existing local directory, the remote file name is used.
- If an upload destination ends with `/`, the local file name is used.

Remote file access is limited by the OS permissions of the user that started
`xshd`. Recursive directory copy is not implemented yet.

## Reference

- [ZJU Computer Networks Lab 7 Documentation](https://zjucomp.net/docs/Lab7_page)
