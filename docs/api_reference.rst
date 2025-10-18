==================================================
PufferBlow API Reference - Developer Documentation
==================================================

This reference documents all available REST API endpoints for PufferBlow developers. The API uses standard HTTP methods (GET, POST, PUT, DELETE) and JSON for request/response formats.

All requests require appropriate authentication headers. Most endpoints require an `auth_token` which can be obtained through the signin process.

Authentication
==============

Most API endpoints require authentication. Include the `auth_token` in your requests in one of these ways:

1. **Query Parameter**: ``?auth_token=your_token_here``
2. **Header**: ``Authorization: Bearer your_token_here``
3. **Request Body**: Include ``auth_token`` field in JSON payload

.. _api-user-routes:

User Routes
===========

These endpoints handle user authentication, account management, and profile operations.

**GET /api/v1/users/signin**

Sign in to an existing account.

**Query Parameters:**

================  ========  ===========
Parameter         Type      Description
================  ========  ===========
username          string    Account username
password          string    Account password
================  ========  ===========

**Response (200 OK):**

.. sourcecode:: json

   {
     "status_code": 200,
     "message": "Signin successfully",
     "auth_token": "user_id.token_string"
   }

**POST /api/v1/users/signup**

Create a new user account.

**Request Body:**

.. sourcecode:: json

   {
     "username": "johndoe",
     "password": "mySecurePassword123!"
   }

**Response (201 Created):**

.. sourcecode:: json

   {
     "status_code": 201,
     "message": "Account created successfully",
     "auth_token": "user_id.token_string",
     "auth_token_expire_time": "2025-10-25T10:00:00Z"
   }

**POST /api/v1/users/profile**

Get current user's profile information. Also supports fetching other users' public profiles.

**Request Body:**

.. sourcecode:: json

   {
     "auth_token": "your_auth_token",
     "user_id": "optional_other_user_id"
   }

**PUT /api/v1/users/profile**

Update user profile information. Supports username, status, password, and about section updates.

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     User's authentication token
new_username      string     Optional new username
status            string     New status message
new_password      string     New password (requires old_password)
old_password      string     Current password (for password changes)
about             string     New about/bio text
================  =========  ===========

**POST /api/v1/users/profile/reset-auth-token**

Reset authentication token (requires password verification).

**Request Body:**

.. sourcecode:: json

   {
     "auth_token": "current_token",
     "password": "current_password"
   }

**POST /api/v1/users/profile/avatar**

Upload user avatar image.

**Form Data:**

================  =========  ===========
Field             Type       Description
================  =========  ===========
auth_token        string     User's authentication token
file              file       Image file (PNG, JPEG, GIF)
================  =========  ===========

**POST /api/v1/users/profile/banner**

Upload user banner image (same format as avatar).

Channel Routes
==============

These endpoints handle channel management, messaging, and message operations.

**GET /api/v1/channels**

Get information about the channels endpoint.

**POST /api/v1/channels/list/**

List all available channels (excludes private channels unless user has access).

**Request Body:**

.. sourcecode:: json

   {
     "auth_token": "your_auth_token"
   }

**POST /api/v1/channels/create/**

Create a new channel. Only server admins or owners can create channels.

**Request Body:**

.. sourcecode:: json

   {
     "auth_token": "admin_token",
     "channel_name": "gaming-discussion",
     "is_private": false
   }

**DELETE /api/v1/channels/{channel_id}/delete**

Delete a channel. Only admins/owners can delete channels.

**PUT /api/v1/channels/{channel_id}/add_user**

Add user to private channel. Admin/owner only.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Target channel
================  =========  ===========

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     Admin authentication token
to_add_user_id    string     User to add to channel
================  =========  ===========

**Response (200 OK):**

.. sourcecode:: json

   {
     "status_code": 200,
     "message": "User ID: 'user_123' added to Channel ID: 'channel_456'"
   }

**DELETE /api/v1/channels/{channel_id}/remove_user**

Remove user from private channel. Admin/owner only.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Target channel
================  =========  ===========

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     Admin authentication token
to_remove_user_id string     User to remove from channel
================  =========  ===========

**Response (200 OK):**

.. sourcecode:: json

   {
     "status_code": 200,
     "message": "User ID: 'user_123' removed from Channel ID: 'channel_456'"
   }

**GET /api/v1/channels/{channel_id}/load_messages**

Load paginated messages from a channel.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Channel to load messages from
================  =========  ===========

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     User authentication token
page              integer    Page number (default: 1)
messages_per_page integer    Messages per page (1-50, default: 20)
================  =========  ===========

**Response (200 OK):**

.. sourcecode:: json

   {
     "status_code": 200,
     "messages": [
       {
         "message_id": "msg_123",
         "sender_user_id": "user_456",
         "channel_id": "channel_789",
         "message": "Hello everyone!",
         "hashed_message": "a1b2c3d4...",
         "username": "johndoe",
         "sent_at": "2025-10-18T07:00:00Z",
         "attachments": ["/api/v1/cdn/file/upload_image.jpg"]
       }
     ]
   }

**POST /api/v1/channels/{channel_id}/send_message**

Send a message to a channel. Supports text and file attachments.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Channel to send message to
================  =========  ===========

**Form Data:**

================  =========  ===========
Field             Type       Description
================  =========  ===========
auth_token        string     User authentication token
message           string     Message text (optional with attachments)
attachments       file(s)    File attachments (optional)
================  =========  ===========

**Response (201 Created):**

.. sourcecode:: json

   {
     "status_code": 201,
     "message": "message sent successfully",
     "message_id": "msg_456",
     "attachments": ["/api/v1/cdn/file/upload_file.jpg"]
   }

**PUT /api/v1/channels/{channel_id}/mark_message_as_read**

Mark a message as read for the current user.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Channel containing the message
================  =========  ===========

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     User authentication token
message_id        string     Message to mark as read
================  =========  ===========

**Response (201 Created):**

.. sourcecode:: json

   {
     "status_code": 201,
     "message": "The message_id was successfully marked as read"
   }

**DELETE /api/v1/channels/{channel_id}/delete_message**

Delete a message from channel. User can delete own messages, admins can delete any.

**URL Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Channel containing the message
================  =========  ===========

**Query Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
auth_token        string     User authentication token
message_id        string     Message to delete
================  =========  ===========

**Response (204 No Content):**

.. sourcecode:: json

   {
     "status_code": 204,
     "message": "The message has been deleted successfully"
   }

File Management (CDN) Routes
=============================

These endpoints handle file uploads, downloads, and CDN management. Most require server owner privileges.

**POST /api/v1/cdn/upload**

Upload file to CDN. Server owner only.

**POST /api/v1/cdn/files**

List files in CDN directory. Server owner only.

**POST /api/v1/cdn/file-info**

Get detailed file information. Server owner only.

**POST /api/v1/cdn/delete-file**

Delete file from CDN. Server owner only.

**GET /api/v1/cdn/file/{file_path}**

Serve CDN file directly.

**POST /api/v1/cdn/cleanup-orphaned**

Clean up orphaned CDN files. Server owner only.

Server Administration Routes
=============================

These endpoints are only available to server owners and administrators for managing server configuration, security, and settings.

**POST /api/v1/blocked-ips/list**

List blocked IP addresses.

**POST /api/v1/blocked-ips/block**

Block an IP address.

**POST /api/v1/blocked-ips/unblock**

Unblock an IP address.

**GET /api/v1/system/server-info**

Get server configuration information.

**GET /api/v1/system/server-stats**

Get server statistics and metrics.

**GET /api/v1/system/server-usage**

Get real-time server resource usage.

**PUT /api/v1/system/server-info**

Update server configuration. Server owner only.

**POST /api/v1/system/upload-avatar**

Upload server avatar. Server owner only.

**POST /api/v1/system/upload-banner**

Upload server banner. Server owner only.

Analytics & Activity Routes
===========================

These endpoints provide charts, metrics, and activity monitoring for server administrators.

**POST /api/v1/system/charts/user-registrations**

Get user registration chart data.

**POST /api/v1/system/charts/message-activity**

Get message activity chart data.

**POST /api/v1/system/charts/online-users**

Get online users chart data.

**POST /api/v1/system/charts/channel-creation**

Get channel creation chart data.

**POST /api/v1/system/charts/user-status**

Get user status distribution chart data.

**POST /api/v1/system/recent-activity**

Get recent server activity events. Admin only.

**POST /api/v1/system/activity-metrics**

Get current activity metrics. Admin only.

**POST /api/v1/system/server-overview**

Get comprehensive server overview. Admin only.

Background Tasks Routes
=======================

These endpoints manage background tasks and automated server operations.

**POST /api/v1/background-tasks/status**

Get status of all background tasks.

**POST /api/v1/background-tasks/run**

Execute a background task on-demand.

General Routes
==============

Miscellaneous endpoints for general server information.

**GET /api/v1/info**

Get basic server information.

**GET /api/v1/system/latest-release**

Get information about the latest PufferBlow release.

WebSocket Routes
================

PufferBlow uses WebSockets for real-time messaging.

**WebSocket Endpoint:** ``ws://your-server:7575/ws/channels/{channel_id}``

**Connection Parameters:**

================  =========  ===========
Parameter         Type       Description
================  =========  ===========
channel_id        string     Channel to connect to
auth_token        string     User authentication token (as query parameter)
================  =========  ===========

**Incoming Messages (Server -> Client):**

.. sourcecode:: json

   {
     "message_id": "msg_123",
     "sender_user_id": "user_456",
     "channel_id": "channel_789",
     "message": "Hello everyone!",
     "username": "johndoe",
     "sent_at": "2025-10-18T07:00:00Z",
     "attachments": ["/api/v1/cdn/file/image.jpg"]
   }

**Outgoing Messages (Client -> Server):**

.. sourcecode:: json

   {
     "type": "read_confirmation",
     "message_id": "msg_123"
   }

Error Responses
===============

All API endpoints may return error responses in the following format:

**400 Bad Request:**
.. sourcecode:: json
   {"detail": "Error description"}

**401 Unauthorized:**
.. sourcecode:: json
   {"detail": "Authentication required"}

**403 Forbidden:**
.. sourcecode:: json
   {"detail": "Access forbidden"}

**404 Not Found:**
.. sourcecode:: json
   {"detail": "Resource not found"}

**409 Conflict:**
.. sourcecode:: json
   {"detail": "Resource conflict"}

**500 Internal Server Error:**
.. sourcecode:: json
   {"detail": "Internal server error"}

Rate Limiting
=============

The API implements rate limiting to prevent abuse:

- **Standard users:** 100 requests per minute
- **Authenticated users:** 200 requests per minute
- **Server owners:** 500 requests per minute

Rate limit headers are included in responses:

================  ===========
Header            Description
================  ===========
X-RateLimit-Limit Total requests allowed per minute
X-RateLimit-Remaining Requests remaining in current window
X-RateLimit-Reset Time when rate limit resets (Unix timestamp)
Retry-After Seconds to wait before retrying (when limit exceeded)
================  ===========

Development Tips
================

**API Base URL:** ``http://your-server:7575/api/v1``

**Debug Mode:** Add ``?debug=1`` to see additional error information

**API Documentation:** Visit ``http://your-server:7575/docs`` for interactive OpenAPI documentation

**Testing:** Use tools like curl, Postman, or HTTPie for testing endpoints

.. code-block:: bash

   # Example API call
   curl -X POST http://localhost:7575/api/v1/users/signin \
     -H "Content-Type: application/json" \
     -d '{"username":"test","password":"test"}'
