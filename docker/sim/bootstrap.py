#!/usr/bin/env python
"""First start of a simulation instance: its server row, an owner, a moderator, some channels, and who may join.

Runs inside the container before `pufferblow serve`, and can run again (it skips what exists).

Env: PUFFERBLOW_DATABASE_URI (as for `serve`), SIM_SERVER_NAME, SIM_JOIN_MODE (open | invite | request).
The owner is `owner` and the moderator `mod`; every simulation password is `simpass123`.
"""

from __future__ import annotations

import os
import sys

PASSWORD = "simpass123"
TEXT_CHANNELS = ("general", "memes", "announcements")
VOICE_CHANNELS = ("lounge", "stand-up")


def main() -> int:
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.core.bootstrap import api_initializer

    database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        print("No database URI (set PUFFERBLOW_DATABASE_URI).", file=sys.stderr)
        return 1
    api_initializer.load_objects(database_uri=database_uri)

    name = os.environ.get("SIM_SERVER_NAME", "Simulation")
    if not api_initializer.server_manager.check_server_exists():
        api_initializer.server_manager.create_server(server_name=name, server_welcome_message=f"Welcome to {name}.")
        print(f"server created: {name} ({api_initializer.database_handler.get_server_id()})")

    users = api_initializer.user_manager
    database = api_initializer.database_handler
    if not users.check_username("owner"):
        users.sign_up(username="owner", password=PASSWORD, is_owner=True)
    if not users.check_username("mod"):
        mod = users.sign_up(username="mod", password=PASSWORD)
        database.update_user_roles(str(mod.user_id), ["moderator"])
    owner_id = str(database.get_user(username="owner").user_id)

    existing = set(database.get_channels_names())
    for channel in TEXT_CHANNELS:
        if channel not in existing:
            api_initializer.channels_manager.create_channel(user_id=owner_id, channel_name=channel, is_private=False, channel_type="text")
    if "staff" not in existing:
        api_initializer.channels_manager.create_channel(user_id=owner_id, channel_name="staff", is_private=True, channel_type="text")
    for channel in VOICE_CHANNELS:
        if channel not in existing:
            api_initializer.channels_manager.create_channel(user_id=owner_id, channel_name=channel, is_private=False, channel_type="voice")

    database.set_join_mode(os.environ.get("SIM_JOIN_MODE", "open"))
    print(f"ready: join mode {database.get_join_mode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
