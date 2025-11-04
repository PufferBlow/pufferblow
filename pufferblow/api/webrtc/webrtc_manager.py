import asyncio
import json
import uuid
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta

try:
    import aiortc
    from aiortc import RTCPeerConnection, RTCIceServer, RTCConfiguration
    from aiortc.contrib.media import MediaRelay
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    RTCPeerConnection = None
    logging.warning("aiortc not available - voice channels will be disabled")

from loguru import logger

# Database utils
from pufferblow.api.database.database_handler import DatabaseHandler

@dataclass
class Participant:
    """Represents a voice channel participant"""
    user_id: str
    username: str
    pc: Optional['RTCPeerConnection'] = None  # Type hint for aiortc
    is_muted: bool = False
    is_deafened: bool = False
    joined_at: datetime = None
    websocket_connection_id: Optional[str] = None

    def __post_init__(self):
        if self.joined_at is None:
            self.joined_at = datetime.now()

@dataclass
class VoiceChannel:
    """Represents a voice channel with multiple participants"""
    channel_id: str
    participants: Dict[str, Participant] = None
    created_at: datetime = None
    max_participants: int = 50  # Default limit for scalability

    def __post_init__(self):
        if self.participants is None:
            self.participants = {}
        if self.created_at is None:
            self.created_at = datetime.now()

class WebRTCManager:
    """
    Manages WebRTC connections for voice channels using aiortc.

    This replaces LiveKit with a direct WebRTC mesh implementation
    that's more scalable and doesn't require external services.
    """

    def __init__(self, database_handler: DatabaseHandler):
        self.database_handler = database_handler
        self.voice_channels: Dict[str, VoiceChannel] = {}
        self.media_relay = MediaRelay() if AIORTC_AVAILABLE else None

        # STUN servers for WebRTC (Google's public STUN servers)
        self.stun_servers = [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302"
        ]

        # ICE configuration
        if AIORTC_AVAILABLE:
            self.ice_servers = [
                RTCIceServer(urls=server) for server in self.stun_servers
            ]
        else:
            self.ice_servers = []

        self.cleanup_task = None
        # Only start cleanup task if there's already a running event loop
        try:
            asyncio.get_running_loop()
            self._start_cleanup_task()
        except RuntimeError:
            # No event loop running, will start cleanup task later via initialize_webrtc_manager
            pass

    def _start_cleanup_task(self):
        """Start background cleanup task for expired connections"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_expired_connections())

    async def _cleanup_expired_connections(self):
        """Periodically clean up expired voice connections"""
        cleanup_interval = 60  # 60 seconds
        disconnection_timeout = 300  # 5 minutes timeout

        logger.info(f"Starting WebRTC cleanup task with {cleanup_interval}s interval and {disconnection_timeout}s timeout")
        cleanup_cycle = 0

        while True:
            try:
                await asyncio.sleep(cleanup_interval)
                cleanup_cycle += 1
                current_time = datetime.now()

                logger.debug(f"Cleanup cycle {cleanup_cycle}: Checking {len(self.voice_channels)} active channels")

                channels_to_cleanup = []
                total_participants_removed = 0

                for channel_id, channel in self.voice_channels.items():
                    participants_to_remove = []
                    channel_participants = len(channel.participants)

                    logger.debug(f"Checking channel {channel_id} with {channel_participants} participants")

                    for user_id, participant in channel.participants.items():
                        # Check if participant has been inactive too long
                        if participant.pc and hasattr(participant.pc, 'connectionState'):
                            connection_state = participant.pc.connectionState
                            logger.debug(f"Participant {user_id} in channel {channel_id} has connection state: {connection_state}")

                            if connection_state == "closed" or connection_state == "failed":
                                participants_to_remove.append((user_id, "connection_state"))
                                logger.warning(f"Removing disconnected participant {user_id} from channel {channel_id} (state: {connection_state})")
                            elif current_time - participant.joined_at > timedelta(seconds=disconnection_timeout):
                                # Check if WebSocket connection is still alive via database lookup
                                websocket_active = self._is_websocket_connection_active(participant.websocket_connection_id)
                                logger.debug(f"WebSocket check for {user_id}: active={websocket_active}")

                                if not websocket_active:
                                    participants_to_remove.append((user_id, "websocket_timeout"))
                                    logger.warning(f"Removing timed out participant {user_id} from channel {channel_id} (joined: {participant.joined_at}, timeout: {disconnection_timeout}s)")
                        else:
                            # Check timeout even for connections without state
                            if current_time - participant.joined_at > timedelta(seconds=disconnection_timeout):
                                participants_to_remove.append((user_id, "general_timeout"))
                                logger.warning(f"Removing generally timed out participant {user_id} from channel {channel_id}")

                    # Actually remove participants
                    for user_id, reason in participants_to_remove:
                        await self._remove_participant(channel_id, user_id)
                        total_participants_removed += 1
                        logger.info(f"Removed participant {user_id} from channel {channel_id} (reason: {reason})")

                    # If channel is empty, mark for cleanup
                    remaining_participants = len(channel.participants)
                    if remaining_participants == 0:
                        channels_to_cleanup.append(channel_id)
                        logger.debug(f"Marking empty channel {channel_id} for cleanup")

                # Clean up empty channels
                for channel_id in channels_to_cleanup:
                    self.voice_channels.pop(channel_id, None)
                    logger.info(f"Cleaned up empty voice channel {channel_id}")

                if total_participants_removed > 0 or len(channels_to_cleanup) > 0:
                    logger.info(f"Cleanup cycle {cleanup_cycle} completed: removed {total_participants_removed} participants, cleaned {len(channels_to_cleanup)} empty channels")

                # Periodic status report
                if cleanup_cycle % 10 == 0:  # Every 10 minutes (10 * 60s)
                    active_channels = len(self.voice_channels)
                    total_participants = sum(len(ch.participants) for ch in self.voice_channels.values())
                    logger.info(f"WebRTC status: {active_channels} active channels, {total_participants} total participants")

            except Exception as e:
                logger.error(f"Error during cleanup cycle {cleanup_cycle}: {str(e)}", exc_info=True)
                # Continue cleanup loop even after errors

    def _is_websocket_connection_active(self, connection_id: Optional[str]) -> bool:
        """
        Check if WebSocket connection is still active.

        This is a simplified check - in production, you'd have a connection registry.
        """
        if not connection_id:
            return False
        # For now, assume connection is active if it exists
        # TODO: Implement proper WebSocket connection tracking
        return True

    def get_user_current_channel(self, user_id: str) -> Optional[str]:
        """
        Get the current voice channel ID for a user.
        Returns None if the user is not in any voice channel.

        Args:
            user_id (str): The user's ID

        Returns:
            Optional[str]: The channel ID if user is in a voice channel, None otherwise
        """
        for channel_id, channel in self.voice_channels.items():
            if user_id in channel.participants:
                return channel_id
        return None

    async def join_voice_channel(self, user_id: str, channel_id: str, websocket_connection_id: str = None) -> dict:
        """
        Join a user to a voice channel.

        Args:
            user_id (str): The user's ID
            channel_id (str): The voice channel ID
            websocket_connection_id (str): ID for WebSocket connection tracking

        Returns:
            dict: Success/error response with WebRTC offer if applicable
        """
        if not AIORTC_AVAILABLE:
            return {"error": "Voice channels are not available - aiortc not installed"}

        # Check if channel exists and supports voice
        channel_data = self.database_handler.get_channel_data(channel_id)
        if not channel_data:
            return {"error": "Channel not found"}

        if not (channel_data.channel_type in ["voice", "mixed"]):
            return {"error": "Channel does not support voice"}

        # Get user info
        user_data = self.database_handler.get_user(user_id)
        if not user_data:
            return {"error": "User not found"}

        username = user_data.username

        # Get or create voice channel
        if channel_id not in self.voice_channels:
            self.voice_channels[channel_id] = VoiceChannel(channel_id=channel_id)

        voice_channel = self.voice_channels[channel_id]

        # Check participant limit
        if len(voice_channel.participants) >= voice_channel.max_participants:
            return {"error": f"Voice channel is full (max {voice_channel.max_participants} participants)"}

        # Check if user is already in channel
        if user_id in voice_channel.participants:
            logger.info(f"User {user_id} rejoining voice channel {channel_id}")
        else:
            logger.info(f"User {user_id} ({username}) joining voice channel {channel_id}")

        # Create WebRTC peer connection
        try:
            pc = RTCPeerConnection(configuration=RTCConfiguration(iceServers=self.ice_servers))
            participant = Participant(
                user_id=user_id,
                username=username,
                pc=pc,
                websocket_connection_id=websocket_connection_id or str(uuid.uuid4())
            )

            voice_channel.participants[user_id] = participant

            # Set up event handlers
            @pc.on("connectionstatechange")
            async def on_connection_state_change():
                logger.info(f"PC connection state for {user_id}: {pc.connectionState}")
                if pc.connectionState == "connected":
                    logger.info(f"WebRTC connection established for user {user_id} in channel {channel_id}")

                # Update database with participant list
                current_participants = list(voice_channel.participants.keys())
                self.database_handler.update_channel_participants(channel_id, current_participants)

            @pc.on("icecandidate")
            async def on_ice_candidate(candidate):
                # This would signal to other peers - simplified in mesh approach
                logger.debug(f"ICE candidate for {user_id}: {candidate}")

            # For mesh WebRTC (all-to-all connections), we'll need to create offers
            # In this simplified version, we focus on signaling approach

            return {
                "status": "joined",
                "channel_id": channel_id,
                "user_id": user_id,
                "participants": len(voice_channel.participants),
                "participant_count": len(voice_channel.participants),
                # Return WebRTC configuration for client
                "webrtc_config": {
                    "ice_servers": self.stun_servers,
                    "channel_type": channel_data.channel_type,
                    "max_participants": voice_channel.max_participants
                }
            }

        except Exception as e:
            logger.error(f"Failed to create WebRTC connection for user {user_id}: {str(e)}")
            # Clean up on error
            if user_id in voice_channel.participants:
                voice_channel.participants.pop(user_id)
            return {"error": f"Failed to join voice channel: {str(e)}"}

    async def leave_voice_channel(self, user_id: str, channel_id: str) -> dict:
        """
        Remove a user from a voice channel.

        Args:
            user_id (str): The user's ID
            channel_id (str): The voice channel ID

        Returns:
            dict: Success/error response
        """
        if not AIORTC_AVAILABLE:
            return {"error": "Voice channels are not available"}

        if channel_id not in self.voice_channels:
            return {"error": "Voice channel not found"}

        voice_channel = self.voice_channels[channel_id]

        if user_id not in voice_channel.participants:
            return {"error": "User not in voice channel"}

        # Remove participant
        participant = voice_channel.participants.pop(user_id)

        logger.info(f"User {user_id} ({participant.username}) left voice channel {channel_id}")

        try:
            # Close WebRTC connection gracefully
            if participant.pc:
                await participant.pc.close()
        except Exception as e:
            logger.warning(f"Error closing WebRTC connection for user {user_id}: {str(e)}")

        # Update database
        current_participants = list(voice_channel.participants.keys()) if voice_channel.participants else []
        self.database_handler.update_channel_participants(channel_id, current_participants)

        # Clean up empty channels
        if not voice_channel.participants:
            self.voice_channels.pop(channel_id, None)
            logger.info(f"Voice channel {channel_id} is now empty and was removed")

        return {
            "status": "left",
            "channel_id": channel_id,
            "participant_count": len(voice_channel.participants)
        }

    def get_voice_channel_status(self, channel_id: str) -> dict:
        """
        Get status of a voice channel including participants.

        Args:
            channel_id (str): The voice channel ID

        Returns:
            dict: Channel status with participant info
        """
        if not AIORTC_AVAILABLE:
            return {"error": "Voice channels are not available"}

        if channel_id not in self.voice_channels:
            return {
                "channel_id": channel_id,
                "participants": [],
                "participant_count": 0,
                "error": "No active voice channel"
            }

        voice_channel = self.voice_channels[channel_id]

        # Build participant info
        participants = []
        for user_id, participant in voice_channel.participants.items():
            participants.append({
                "user_id": user_id,
                "username": participant.username,
                "is_muted": participant.is_muted,
                "is_deafened": participant.is_deafened,
                "joined_at": participant.joined_at.isoformat() if participant.joined_at else None,
                "connection_state": participant.pc.connectionState if participant.pc and hasattr(participant.pc, 'connectionState') else "unknown"
            })

        return {
            "channel_id": channel_id,
            "participants": participants,
            "participant_count": len(participants),
            "max_participants": voice_channel.max_participants,
            "created_at": voice_channel.created_at.isoformat()
        }

    async def _remove_participant(self, channel_id: str, user_id: str):
        """Helper to remove a participant from a channel"""
        if channel_id not in self.voice_channels:
            return

        voice_channel = self.voice_channels[channel_id]

        if user_id not in voice_channel.participants:
            return

        participant = voice_channel.participants.pop(user_id)

        try:
            if participant.pc:
                await participant.pc.close()
        except Exception as e:
            logger.warning(f"Error closing connection for {user_id}: {str(e)}")

        # Update database participant list
        current_participants = list(voice_channel.participants.keys())
        self.database_handler.update_channel_participants(channel_id, current_participants)

        logger.info(f"Removed participant {user_id} from voice channel {channel_id}")

    async def mute_participant(self, channel_id: str, user_id: str, muted: bool) -> dict:
        """Mute or unmute a participant"""
        if not AIORTC_AVAILABLE:
            return {"error": "Voice channels are not available"}

        if channel_id not in self.voice_channels:
            return {"error": "Voice channel not found"}

        voice_channel = self.voice_channels[channel_id]
        if user_id not in voice_channel.participants:
            return {"error": "Participant not found"}

        participant = voice_channel.participants[user_id]
        participant.is_muted = muted

        logger.info(f"User {user_id} {'muted' if muted else 'unmuted'} in channel {channel_id}")

        return {
            "status": "success",
            "user_id": user_id,
            "channel_id": channel_id,
            "is_muted": muted
        }

    def get_channel_participants(self, channel_id: str) -> List[dict]:
        """Get list of participants in a channel"""
        if channel_id not in self.voice_channels:
            return []

        voice_channel = self.voice_channels[channel_id]
        participants = []

        for user_id, participant in voice_channel.participants.items():
            participants.append({
                "user_id": user_id,
                "username": participant.username,
                "is_muted": participant.is_muted,
                "is_deafened": participant.is_deafened,
                "joined_at": participant.joined_at.isoformat() if participant.joined_at else None
            })

        return participants

    def is_channel_voice_enabled(self, channel_id: str) -> bool:
        """Check if a channel is voice-enabled"""
        channel_data = self.database_handler.get_channel_data(channel_id)
        return channel_data and channel_data.channel_type in ["voice", "mixed"]

    def get_webrtc_config(self) -> dict:
        """Return WebRTC configuration for clients"""
        return {
            "ice_servers": self.stun_servers,
            "bundle_policy": "balanced",
            "rtcp_mux_policy": "require",
            # Signaling will be handled via WebSockets
            "signaling_method": "websocket_mesh"
        }

    async def shutdown(self):
        """Clean shutdown of all connections"""
        logger.info("Shutting down WebRTC manager...")

        # Close all peer connections
        for channel_id, channel in self.voice_channels.items():
            for user_id, participant in channel.participants.items():
                try:
                    if participant.pc:
                        await participant.pc.close()
                except Exception as e:
                    logger.warning(f"Error closing PC for {user_id}: {str(e)}")

        self.voice_channels.clear()

        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("WebRTC manager shutdown complete")

# Singleton instance
webrtc_manager = WebRTCManager(None)  # Will be initialized with database handler

def get_webrtc_manager() -> WebRTCManager:
    """Get the global WebRTC manager instance"""
    return webrtc_manager

def initialize_webrtc_manager(database_handler: DatabaseHandler):
    """Initialize the WebRTC manager with database handler"""
    global webrtc_manager
    new_manager = WebRTCManager(database_handler)

    # Start cleanup task now that we have an event loop (during server startup)
    try:
        asyncio.get_running_loop()
        new_manager._start_cleanup_task()
        logger.info("Started WebRTC cleanup task")
    except RuntimeError:
        # If still no event loop, the task will start later when the event loop is available
        logger.warning("Event loop not yet available, cleanup task will start later")

    webrtc_manager = new_manager

# Export for import
if AIORTC_AVAILABLE:
    __all__ = ['WebRTCManager', 'get_webrtc_manager', 'initialize_webrtc_manager', 'AIORTC_AVAILABLE']
else:
    __all__ = ['WebRTCManager', 'get_webrtc_manager', 'initialize_webrtc_manager']
    logger.warning("aiortc not available - WebRTC voice channels will be disabled")
