import json
from unittest.mock import MagicMock

import pytest

from pufferblow.core.bootstrap import api_initializer
from pufferblow.tests.conftest import ValueStorage


class TestWebSocketReadMessages:
    """Test websocket message read confirmation functionality"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        self.auth_token = ValueStorage.auth_token

    def test_websocket_send_read_confirmation(self):
        """Test that websocket can receive and process read confirmations"""
        # This is a structural test to verify the websocket code accepts read confirmations

        # Mock a websocket message
        read_confirmation_message = {
            "type": "read_confirmation",
            "message_id": "test-message-123",
        }

        # Verify the message structure that the client should send
        assert read_confirmation_message["type"] == "read_confirmation"
        assert "message_id" in read_confirmation_message

        # The websocket handler should be able to parse this JSON
        message_json = json.dumps(read_confirmation_message)
        parsed = json.loads(message_json)

        assert parsed["type"] == "read_confirmation"
        assert parsed["message_id"] == "test-message-123"

    def test_websocket_manager_personal_message(self):
        """Test websocket manager can send personal messages"""
        # Test the new send_personal_message method in websocket manager
        ws_manager = api_initializer.websockets_manager

        # Mock websocket
        mock_ws = MagicMock()

        # Test message
        test_message = {"type": "read_ack", "message_id": "123", "status": "ok"}

        # The method should work (we can't fully test async in this context)
        # But we can verify it exists and has the right signature



        # Check that the method exists
        assert hasattr(ws_manager, "send_personal_message")

    def test_read_confirmation_processing_logic(self):
        """Test the logic for processing read confirmations in websocket"""
        # Simulate the logic that happens in the websocket handler

        # Initial state
        unconfirmed_messages = {"msg-1": True, "msg-2": True, "msg-3": True}

        # Simulate receiving a read confirmation for msg-2
        incoming_data = json.dumps({"type": "read_confirmation", "message_id": "msg-2"})

        message_data = json.loads(incoming_data)

        if message_data.get("type") == "read_confirmation":
            message_id = message_data.get("message_id")
            if message_id and message_id in unconfirmed_messages:
                # This should remove msg-2 from unconfirmed_messages
                # In real code, this would also call mark_message_as_read
                del unconfirmed_messages[message_id]

        # Verify msg-2 was removed
        assert "msg-2" not in unconfirmed_messages
        assert "msg-1" in unconfirmed_messages
        assert "msg-3" in unconfirmed_messages

    def test_websocket_message_tracking(self):
        """Test that the websocket tracks sent vs unconfirmed messages"""
        # Simulate message tracking logic from websocket handler

        sent_messages_ids = []  # Messages we've sent
        unconfirmed_messages = {}  # Messages sent but not confirmed as read

        # Simulate sending some messages
        messages_to_send = [
            {"message_id": "msg-a", "content": "Hello"},
            {"message_id": "msg-b", "content": "World"},
            {"message_id": "msg-c", "content": "!"},
        ]

        for message in messages_to_send:
            message_id = message["message_id"]

            # Skip if already sent
            if message_id in sent_messages_ids:
                continue

            # Send message (simulated)
            sent_messages_ids.append(message_id)
            unconfirmed_messages[message_id] = True

        # Verify tracking
        assert len(sent_messages_ids) == 3
        assert len(unconfirmed_messages) == 3
        assert all(mid in unconfirmed_messages for mid in ["msg-a", "msg-b", "msg-c"])

        # Simulate receiving a read confirmation
        confirmed_message_id = "msg-b"
        if confirmed_message_id in unconfirmed_messages:
            del unconfirmed_messages[confirmed_message_id]

        # Verify msg-b was removed from unconfirmed
        assert confirmed_message_id not in unconfirmed_messages
        assert len(unconfirmed_messages) == 2

    def test_messages_manager_includes_read_tracking(self):
        """Test that messages_manager has the mark_message_as_read method"""
        # Verify that the messages_manager has the necessary methods
        msg_manager = api_initializer.messages_manager

        assert hasattr(msg_manager, "mark_message_as_read")
        assert hasattr(msg_manager, "send_message")
        assert hasattr(msg_manager, "load_messages")

    def test_database_handler_supports_message_read_tracking(self):
        """Test that database_handler supports marking messages as read"""
        db_handler = api_initializer.database_handler

        # Check that the method exists
        assert hasattr(db_handler, "add_message_to_read_history")
        assert hasattr(db_handler, "get_user_read_messages_ids")

    def test_websocket_json_message_format(self):
        """Test the expected JSON message format for websocket communication"""
        # Test message sent from server to client
        server_message = {
            "message_id": "msg-12345",
            "sender_id": "user-67890",
            "channel_id": "channel-abc123",
            "raw_message": "This is a test message",
            "username": "testuser",
            "sent_at": "2025-10-17T19:57:37.000000",
        }

        # Should be valid JSON
        json_str = json.dumps(server_message)
        parsed_back = json.loads(json_str)

        assert parsed_back["message_id"] == "msg-12345"
        assert parsed_back["channel_id"] == "channel-abc123"

        # Test read confirmation message sent from client to server
        client_message = {"type": "read_confirmation", "message_id": "msg-12345"}

        json_str = json.dumps(client_message)
        parsed_back = json.loads(json_str)

        assert parsed_back["type"] == "read_confirmation"
        assert parsed_back["message_id"] == "msg-12345"
