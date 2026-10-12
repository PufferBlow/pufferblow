"""The user roster the scenarios run against.

Two users per instance, not one, so the scenarios can exercise BOTH the
federated path (alice@A <-> bob@B) AND the local-delivery path
(alice@A <-> carol@A) without a third instance. `admin_*` is a separate,
privileged account (owner role) seeded directly by `bootstrap_instance.py`
— public signup never grants privileges, so channel creation (needed for
the channel-to-DM forwarding scenario) has to go through an account that
was never created over HTTP at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from common import INSTANCE_A, INSTANCE_B, handle_for, signup_or_signin


@dataclass
class User:
    base_url: str
    username: str
    password: str
    auth_token: str = ""
    user_id: str = ""

    @property
    def handle(self) -> str:
        return handle_for(self.base_url, self.username)

    def actor_uri(self) -> str:
        return f"{self.base_url}/ap/users/{self.user_id}"


# Primary cross-instance pair — used by most scenarios.
ALICE = User(INSTANCE_A, "fed_alice", "alicepass123")
BOB = User(INSTANCE_B, "fed_bob", "bobpass123")

# Secondary pair — one per instance again, so "more than two users" and
# same-instance (local-delivery) DMs both get real coverage.
CAROL = User(INSTANCE_A, "fed_carol", "carolpass123")
DAVE = User(INSTANCE_B, "fed_dave", "davepass123")

# Owner-privileged accounts, one per instance — seeded by bootstrap_instance.py
# with is_owner=True, never created over the public signup route. Only
# used for channel-creation-requiring scenarios (forwarding a channel
# message into a DM).
ADMIN_A = User(INSTANCE_A, "fed_admin_a", "adminpass123")
ADMIN_B = User(INSTANCE_B, "fed_admin_b", "adminpass123")

ALL_USERS = (ALICE, BOB, CAROL, DAVE, ADMIN_A, ADMIN_B)


def sign_in_all() -> None:
    """Sign up (or sign in, if already present from a prior run) every user
    in `ALL_USERS`, filling in `auth_token`/`user_id` in place.
    """
    for user in ALL_USERS:
        user.auth_token, user.user_id = signup_or_signin(user.base_url, user.username, user.password)
