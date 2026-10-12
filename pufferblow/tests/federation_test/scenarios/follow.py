"""Follow / Accept / followers+following collections / Undo(Follow).

Covers both cross-instance pairs (alice<->bob, carol<->dave) so a
regression that only shows up with a second concurrent follow relationship
(e.g. the `direction` column fix) has two independent chances to surface.
"""

from __future__ import annotations

import httpx

from common import Reporter
from topology import ALICE, BOB, CAROL, DAVE


def _follow_and_verify(reporter: Reporter, follower, followee) -> None:
    resp = httpx.post(
        f"{follower.base_url}/api/v1/federation/follow",
        json={"auth_token": follower.auth_token, "remote_handle": followee.handle},
        timeout=15.0,
    )
    reporter.check(f"{follower.username} follows {followee.username}", resp.status_code == 200, resp.text)

    followers_page = httpx.get(
        f"{followee.base_url}/ap/users/{followee.user_id}/followers", params={"page": 1}, timeout=5.0
    ).json()
    reporter.check(
        f"{followee.username}'s followers page includes {follower.username}",
        follower.actor_uri() in followers_page.get("orderedItems", []),
        str(followers_page),
    )

    following_page = httpx.get(
        f"{follower.base_url}/ap/users/{follower.user_id}/following", params={"page": 1}, timeout=5.0
    ).json()
    reporter.check(
        f"{follower.username}'s following page includes {followee.username} (direction column)",
        followee.actor_uri() in following_page.get("orderedItems", []),
        str(following_page),
    )


def _unfollow_and_verify(reporter: Reporter, follower, followee) -> None:
    resp = httpx.post(
        f"{follower.base_url}/api/v1/federation/unfollow",
        json={"auth_token": follower.auth_token, "remote_handle": followee.handle},
        timeout=15.0,
    )
    reporter.check(f"{follower.username} unfollows {followee.username}", resp.status_code == 200, resp.text)

    followers_page = httpx.get(
        f"{followee.base_url}/ap/users/{followee.user_id}/followers", params={"page": 1}, timeout=5.0
    ).json()
    reporter.check(
        f"{followee.username}'s followers page no longer includes {follower.username} after Undo",
        follower.actor_uri() not in followers_page.get("orderedItems", []),
        str(followers_page),
    )


def run(reporter: Reporter) -> None:
    reporter.section("Follow / Accept / collections / Undo — pair 1 (alice -> bob)")
    _follow_and_verify(reporter, ALICE, BOB)

    reporter.section("Follow / Accept / collections / Undo — pair 2 (dave -> carol)")
    _follow_and_verify(reporter, DAVE, CAROL)

    reporter.section("Unfollow — pair 1")
    _unfollow_and_verify(reporter, ALICE, BOB)

    reporter.section("Unfollow — pair 2")
    _unfollow_and_verify(reporter, DAVE, CAROL)
