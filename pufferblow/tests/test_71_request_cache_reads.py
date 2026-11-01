"""One request reads a cache key from memcached once; the rest of its reads are answered from memory."""

from __future__ import annotations

import pickle

from pufferblow.api.cache.memcache import MemcacheCache, begin_request_reads, end_request_reads


class CountingClient:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.gets = 0

    def get(self, key):
        self.gets += 1
        return self.store.get(key)

    def set(self, key, value, expire=0):
        self.store[key] = value

    def delete(self, key):
        self.store.pop(key, None)


def make() -> tuple[MemcacheCache, CountingClient]:
    cache = MemcacheCache(host="x", port=1, default_ttl=60)
    client = CountingClient()
    cache._client = client
    return cache, client


def test_a_request_reads_a_key_from_the_cache_once():
    cache, client = make()
    client.store["user:1"] = pickle.dumps({"name": "ada"})
    token = begin_request_reads()
    try:
        for _ in range(5):
            assert cache.get("user:1") == {"name": "ada"}
        assert client.gets == 1
    finally:
        end_request_reads(token)


def test_each_read_is_its_own_copy_so_one_caller_cannot_change_what_another_sees():
    cache, client = make()
    client.store["k"] = pickle.dumps({"roles": ["user"]})
    token = begin_request_reads()
    try:
        first = cache.get("k")
        first["roles"].append("owner")
        assert cache.get("k") == {"roles": ["user"]}
    finally:
        end_request_reads(token)


def test_a_miss_is_remembered_too_until_the_request_writes_the_key():
    cache, client = make()
    token = begin_request_reads()
    try:
        assert cache.get("k") is None and cache.get("k") is None
        assert client.gets == 1
        cache.set("k", {"v": 1})
        assert cache.get("k") == {"v": 1} and client.gets == 1  # what it just wrote, without asking again
    finally:
        end_request_reads(token)


def test_a_delete_in_the_request_is_seen_by_its_next_read():
    cache, client = make()
    client.store["k"] = pickle.dumps(1)
    token = begin_request_reads()
    try:
        assert cache.get("k") == 1
        cache.delete("k")
        assert cache.get("k") is None
        assert client.gets == 2  # the read after a delete asks again
    finally:
        end_request_reads(token)


def test_outside_a_request_nothing_is_remembered():
    cache, client = make()
    client.store["k"] = pickle.dumps(1)
    cache.get("k")
    cache.get("k")
    assert client.gets == 2


def test_one_request_does_not_see_the_reads_of_another():
    cache, client = make()
    client.store["k"] = pickle.dumps(1)
    for _ in range(2):
        token = begin_request_reads()
        try:
            cache.get("k")
        finally:
            end_request_reads(token)
    assert client.gets == 2
