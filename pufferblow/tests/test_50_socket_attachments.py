"""Sending files over the socket: upload.begin / upload.chunk / upload.abort, then message.create with upload_ids.

The staging store is tested on its own first; the second half runs the real commands against a temporary
storage directory.
"""

from __future__ import annotations

import base64
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from pufferblow.api.errors import ApiError
from pufferblow.api.uploads.staging import CHUNK_BYTES, MAX_OPEN_PER_PRINCIPAL, UploadStaging
from pufferblow.core.bootstrap import api_initializer
from pufferblow.tests.test_30_command_protocol import _attach, _command, _context, _new_channel, _run, _signup

MB = 1024 * 1024


# ── the staging store ─────────────────────────────────────────────


def _staging(limit_mb: int = 1, **kw) -> UploadStaging:
    return UploadStaging(lambda: limit_mb * MB, **kw)


def test_chunks_must_arrive_in_order_and_add_up_exactly():
    staging = _staging()
    upload = staging.begin("u1", "a.txt", "text/plain", 10)

    staging.append("u1", upload.upload_id, 0, b"hello")
    with pytest.raises(ApiError):  # skipping ahead
        staging.append("u1", upload.upload_id, 2, b"world")
    with pytest.raises(ApiError):  # more than the declared size
        staging.append("u1", upload.upload_id, 1, b"world!")
    upload, duplicate = staging.append("u1", upload.upload_id, 1, b"world")

    assert not duplicate and upload.complete and upload.received == 10
    [file] = staging.collect("u1", [upload.upload_id])
    assert file.file.read() == b"helloworld" and file.filename == "a.txt"


def test_a_retried_chunk_is_a_no_op():
    staging = _staging()
    upload = staging.begin("u1", "a.bin", None, 4)
    staging.append("u1", upload.upload_id, 0, b"ab")
    again, duplicate = staging.append("u1", upload.upload_id, 0, b"ab")  # the ack was lost, so the client resent it
    assert duplicate and again.received == 2


def test_an_unfinished_upload_cannot_be_used():
    staging = _staging()
    upload = staging.begin("u1", "a.bin", None, 4)
    staging.append("u1", upload.upload_id, 0, b"ab")
    with pytest.raises(ApiError):
        staging.collect("u1", [upload.upload_id])


def test_uploads_belong_to_whoever_began_them():
    staging = _staging()
    upload = staging.begin("alice", "a.bin", None, 2)
    for action in (
        lambda: staging.append("bob", upload.upload_id, 0, b"xx"),
        lambda: staging.collect("bob", [upload.upload_id]),
        lambda: staging.abort("bob", upload.upload_id),
    ):
        with pytest.raises(ApiError) as caught:
            action()
        assert caught.value.status == 404  # the same answer as for one that does not exist
    staging.discard("bob", [upload.upload_id])  # and bob cannot discard it either
    assert staging.open_count("alice") == 1


def test_size_and_count_limits():
    staging = _staging(limit_mb=1)
    for size in (0, MB + 1):
        with pytest.raises(ApiError):
            staging.begin("u1", "big.bin", None, size)
    for _ in range(MAX_OPEN_PER_PRINCIPAL):
        staging.begin("u1", "a.bin", None, 10)
    with pytest.raises(ApiError) as caught:
        staging.begin("u1", "one-too-many.bin", None, 10)
    assert caught.value.status == 429
    staging.begin("someone-else", "a.bin", None, 10)  # another principal is unaffected


def test_the_whole_process_has_a_limit_too():
    staging = _staging(limit_mb=1, max_total_bytes=1500)
    staging.begin("a", "x", None, 1000)
    with pytest.raises(ApiError):
        staging.begin("b", "y", None, 1000)


def test_a_chunk_cannot_exceed_the_chunk_size():
    staging = _staging()
    upload = staging.begin("u1", "a.bin", None, MB)
    with pytest.raises(ApiError):
        staging.append("u1", upload.upload_id, 0, b"x" * (CHUNK_BYTES + 1))


def test_uploads_expire():
    now = [0.0]
    staging = _staging(clock=lambda: now[0], ttl_seconds=60)
    upload = staging.begin("u1", "a.bin", None, 2)
    now[0] = 61
    with pytest.raises(ApiError):
        staging.append("u1", upload.upload_id, 0, b"xx")
    assert staging.open_count() == 0


def test_discard_and_abort_free_the_upload():
    staging = _staging()
    one, two = staging.begin("u1", "a", None, 1), staging.begin("u1", "b", None, 1)
    staging.abort("u1", one.upload_id)
    staging.discard("u1", [two.upload_id])
    assert staging.open_count() == 0


# ── over the commands ─────────────────────────────────────────────


def _point_storage_at(tmp_path: Path) -> None:
    api_initializer.config.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.STORAGE_PATH = str(tmp_path)
    api_initializer.storage_manager.config["storage_path"] = str(tmp_path)
    if hasattr(api_initializer.storage_manager.backend, "storage_path"):
        api_initializer.storage_manager.backend.storage_path = tmp_path


async def _send_file(ctx, name: str, content_type: str, payload: bytes) -> str:
    """Upload ``payload`` chunk by chunk and return the upload id."""
    begun = await _run(ctx, _command("upload.begin", {"name": name, "content_type": content_type, "size": len(payload)}))
    assert begun["type"] == "ack", begun
    upload_id = begun["data"]["result"]["upload_id"]
    chunk = begun["data"]["result"]["chunk_size"]
    for index, start in enumerate(range(0, len(payload), chunk)):
        part = base64.b64encode(payload[start : start + chunk]).decode("ascii")
        reply = await _run(ctx, _command("upload.chunk", {"upload_id": upload_id, "index": index, "data": part}))
        assert reply["type"] == "ack", reply
    return upload_id


def _png(width: int = 40, height: int = 30) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), "red").save(buffer, format="PNG")
    return buffer.getvalue()


async def test_a_message_with_files_sent_over_the_socket(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    sock = _attach(ctx)

    image = _png()
    big_text = b"line of text\n" * 6000  # more than one chunk
    image_id = await _send_file(ctx, "pic.png", "image/png", image)
    text_id = await _send_file(ctx, "notes.txt", "text/plain", big_text)

    reply = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "two files", "upload_ids": [image_id, text_id], "nonce": "n1"}))

    assert reply["type"] == "ack", reply
    attachments = reply["data"]["result"]["message"]["attachments"]
    assert [a["filename"] for a in attachments] == ["pic.png", "notes.txt"]
    assert attachments[0]["type"] == "image/png" and attachments[0]["size"] == len(image)
    assert attachments[1]["size"] == len(big_text)
    # the event carries the same attachments, and the files are really in storage
    [event] = sock.events("message.created")
    assert [a["filename"] for a in event["data"]["attachments"]] == ["pic.png", "notes.txt"]
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file()) >= 2
    # the staged uploads are used up
    assert api_initializer.upload_staging.open_count() == 0


async def test_a_message_can_be_just_files(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)

    upload_id = await _send_file(ctx, "pic.png", "image/png", _png())
    reply = await _run(ctx, _command("message.create", {"channel_id": channel, "upload_ids": [upload_id]}))

    assert reply["type"] == "ack" and len(reply["data"]["result"]["message"]["attachments"]) == 1


async def test_a_retry_with_the_same_nonce_after_a_lost_ack_makes_one_message(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    upload_id = await _send_file(ctx, "pic.png", "image/png", _png())

    body = {"channel_id": channel, "content": "once", "upload_ids": [upload_id], "nonce": "same"}
    first = await _run(ctx, _command("message.create", body))
    second = await _run(ctx, _command("message.create", body))

    assert first["type"] == "ack" and second["type"] == "ack"
    assert second["data"].get("duplicate") is True
    assert second["data"]["result"]["message"]["id"] == first["data"]["result"]["message"]["id"]


async def test_a_file_the_storage_refuses_fails_the_send_and_can_be_retried(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    token = _signup(client)
    channel = _new_channel(token)
    ctx = _context(token, channel)
    # an extension the instance does not allow
    upload_id = await _send_file(ctx, "run.exe", "application/octet-stream", b"MZ" + b"\x00" * 64)

    reply = await _run(ctx, _command("message.create", {"channel_id": channel, "content": "bad file", "upload_ids": [upload_id]}))

    assert reply["type"] == "error" and reply["error"]["code"] == "VALIDATION_FAILED"
    assert api_initializer.upload_staging.open_count() == 1  # still staged: nothing was lost by the refusal


async def test_other_people_cannot_attach_my_upload(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    alice, bob = _signup(client), _signup(client)
    channel = _new_channel(alice)
    alice_ctx, bob_ctx = _context(alice, channel), _context(bob, channel)
    upload_id = await _send_file(alice_ctx, "pic.png", "image/png", _png())

    reply = await _run(bob_ctx, _command("message.create", {"channel_id": channel, "content": "stolen", "upload_ids": [upload_id]}))

    assert reply["type"] == "error" and reply["error"]["code"] == "NOT_FOUND"


async def test_someone_who_cannot_post_cannot_use_uploads_to_do_so(client: TestClient, tmp_path: Path):
    _point_storage_at(tmp_path)
    owner, outsider = _signup(client), _signup(client)
    private = _new_channel(owner, private=True)
    outsider_ctx = _context(outsider, private)
    upload_id = await _send_file(outsider_ctx, "pic.png", "image/png", _png())

    reply = await _run(outsider_ctx, _command("message.create", {"channel_id": private, "content": "let me in", "upload_ids": [upload_id]}))

    assert reply["type"] == "error"
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]  # refused before anything was stored


async def test_bad_chunks_are_refused_with_clear_errors(client: TestClient):
    token = _signup(client)
    ctx = _context(token, _new_channel(token))
    begun = await _run(ctx, _command("upload.begin", {"name": "a.bin", "size": 6}))
    upload_id = begun["data"]["result"]["upload_id"]

    not_base64 = await _run(ctx, _command("upload.chunk", {"upload_id": upload_id, "index": 0, "data": "%%%not-base64%%%"}))
    skipped = await _run(ctx, _command("upload.chunk", {"upload_id": upload_id, "index": 3, "data": base64.b64encode(b"abc").decode()}))
    unknown = await _run(ctx, _command("upload.chunk", {"upload_id": "upl_nope", "index": 0, "data": "YQ=="}))
    too_big = await _run(ctx, _command("upload.begin", {"name": "huge.bin", "size": 10**12}))

    for reply in (not_base64, skipped, too_big):
        assert reply["type"] == "error" and reply["error"]["code"] == "VALIDATION_FAILED", reply
    assert unknown["type"] == "error" and unknown["error"]["code"] == "NOT_FOUND"


async def test_aborting_frees_the_upload(client: TestClient):
    token = _signup(client)
    ctx = _context(token, _new_channel(token))
    upload_id = (await _run(ctx, _command("upload.begin", {"name": "a.bin", "size": 6})))["data"]["result"]["upload_id"]

    aborted = await _run(ctx, _command("upload.abort", {"upload_id": upload_id}))
    again = await _run(ctx, _command("upload.abort", {"upload_id": upload_id}))

    assert aborted["type"] == "ack" and aborted["data"]["result"]["aborted"] is True
    assert again["type"] == "error" and again["error"]["code"] == "NOT_FOUND"
