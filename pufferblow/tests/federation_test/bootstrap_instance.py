#!/usr/bin/env python
"""One-shot, non-interactive bootstrap for a federation-test instance.

`pufferblow setup --setup-server` normally creates the server row
interactively (prompts for a name/welcome message). That's fine for a human
running it once, but devp manages this as a headless process that must
start, finish, and exit on its own — so this does the same thing
(`ServerManager.create_server`) driven entirely by environment variables,
then prints a line `devp.federation.toml`'s `ready_when` regex matches, so
the paired `pufferblow serve` process only starts once this is done.

Idempotent: skips server creation if the row already exists, so re-running
devp (which re-runs every `[[process]]` on each session) is harmless.

Also seeds one owner-privileged account and one public channel with a
seed message in it — both needed by `scenarios/forwarding.py`'s
channel-to-DM case, and neither obtainable through the public signup
route (which never grants privileges). `scenarios/topology.py`'s
`ADMIN_A`/`ADMIN_B` sign IN to whichever of these this process created —
they must match `FEDERATION_TEST_ADMIN_USERNAME` below exactly.

Env vars (all optional except PUFFERBLOW_DATABASE_URI, which `serve` also
requires):
  PUFFERBLOW_DATABASE_URI        -- required, same as `pufferblow serve`
  FEDERATION_TEST_SERVER_NAME    -- default "Federation Test Instance"
  FEDERATION_TEST_ADMIN_USERNAME -- default "fed_admin"
  FEDERATION_TEST_ADMIN_PASSWORD -- default "adminpass123"
  FEDERATION_TEST_CHANNEL_NAME   -- default "general"
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.core.bootstrap import api_initializer

    database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        print(
            "No database URI resolved (set PUFFERBLOW_DATABASE_URI). "
            "This should be set by devp.federation.toml — check the process's "
            "`env` table if you're running this by hand.",
            file=sys.stderr,
        )
        return 1

    api_initializer.load_objects(database_uri=database_uri)

    if api_initializer.server_manager.check_server_exists():
        print("Server row already exists — nothing to do.")
    else:
        server_name = os.environ.get("FEDERATION_TEST_SERVER_NAME", "Federation Test Instance")
        api_initializer.server_manager.create_server(
            server_name=server_name,
            server_welcome_message=f"Local federation test instance ({server_name}).",
        )
        print(f"Server row created: {server_name!r}")

    admin_username = os.environ.get("FEDERATION_TEST_ADMIN_USERNAME", "fed_admin")
    admin_password = os.environ.get("FEDERATION_TEST_ADMIN_PASSWORD", "adminpass123")
    if api_initializer.user_manager.check_username(admin_username):
        print(f"Admin account {admin_username!r} already exists — nothing to do.")
        admin_user_id = str(api_initializer.database_handler.get_user(username=admin_username).user_id)
    else:
        admin_user = api_initializer.user_manager.sign_up(
            username=admin_username, password=admin_password, is_owner=True
        )
        admin_user_id = str(admin_user.user_id)
        print(f"Admin account created: {admin_username!r}")

    channel_name = os.environ.get("FEDERATION_TEST_CHANNEL_NAME", "general")
    if channel_name in api_initializer.database_handler.get_channels_names():
        print(f"Channel {channel_name!r} already exists — nothing to do.")
    else:
        channel = api_initializer.channels_manager.create_channel(
            user_id=admin_user_id, channel_name=channel_name, is_private=False, channel_type="text"
        )
        api_initializer.messages_manager.send_message(
            channel_id=str(channel.channel_id),
            user_id=admin_user_id,
            message="Welcome to the federation test channel — this message is forwarded into a DM by scenarios/forwarding.py.",
        )
        print(f"Channel {channel_name!r} created with a seed message.")

    # Matched by `ready_when` in devp.federation.toml — must be the last line.
    print("BOOTSTRAP_COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
