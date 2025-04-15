# What is Shellij?
Shellij is a thin wrapper around the popluar terminal multiplexer [zellij](https://github.com/zellij-org/zellij).
Simplify using Zellij over SSH.

# Dependencies

- Zellij must be installed BOTH locally and on the remote server
- [fzf](https://github.com/junegunn/fzf?tab=readme-ov-file#installation) is required on the local machine

# Features

Shellij features a subset of the common commands for interacting with both SSH and Zellij together.

Create and attach to a new Zellij session on a remote server

```sh
shellij user@remote.com create session-name
```

Delete a Zellij session on a remote server
```sh
shellij user@192.168.0.1 delete session-name
```

List all Zellij sessions on a remote server
```sh
shellij user@remote.com list
```

When no subcommands are provided one of three things occur:
```sh
shellij user@remote.com
```
1. If no sessions are found then Shellij will create and attach to the newly created session
2. If only a single session is found then Shellij will automatically attach to that session
3. If multiple sessions are found then you will be prompted to select a session via fzf


# Should you use this?
Probably not.
