# User guide

You want to **join a Pufferblow community** or **stand up a small
instance** for friends or family. This section is for you.

If you're operating a production instance for a larger group, the
[Operator guide](../operator/index.md) has more depth on backups,
federation, and recovery.

## Start here

- **[Install your own server](install.md)** — Docker-first
  quickstart. Boots the API, database, voice SFU, and TURN
  relay with one command.

## Connecting to a server you didn't host

Use the official desktop or web client at
[github.com/PufferBlow/client](https://github.com/PufferBlow/client).
Point it at your home instance's hostname (e.g.
`chat.example.com`) and sign in or create an account there.

Each Pufferblow account is **locked to the instance it was
created on**. Federation moves *messages* across instances, not
*logins* — so signing up on `example.org` doesn't give you an
account on `friend.network`. You can follow users on other
instances and DM them; channels stay local.
