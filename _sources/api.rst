========================================
Understanding the PufferBlow API
========================================

What is the PufferBlow API?
===========================

The PufferBlow API is the heart of your self-hosted chat platform. It's a RESTful web service built with FastAPI that provides all the functionality needed to run a modern chat server. Think of it as the backend that powers features like sending messages, managing channels, handling user accounts, and storing files - just like how Discord or Slack work, but completely under your control.

Since PufferBlow is **decentralized**, there's no central server that everyone connects to. Instead, each community or individual hosts their own API server, giving them full control over their data, users, and message history. This approach ensures privacy and prevents any single point of failure or surveillance.

Key Features of the API
========================

.. list-table:: API Capabilities
   :header-rows: 1
   :widths: 30 70

   * - Feature Category
     - What It Enables
   * - **User Management**
     - Account creation, login, profile management, avatar/picture uploads, authentication tokens
   * - **Channel Management**
     - Create public and private channels, manage memberships, set permissions
   * - **Messaging**
     - Send text messages, attachments (images, videos, files), real-time messaging via WebSocket
   * - **File Sharing**
     - Upload and share files, images, and documents with automatic organization and duplicate detection
   * - **Security**
     - Encrypted data storage, rate limiting, IP blocking, secure authentication
   * - **Analytics**
     - User activity tracking, message statistics, server usage monitoring, charts and reports
   * - **Admin Controls**
     - Server configuration, user moderation, content management, system settings

Why Self-Hosting Matters
=========================

With PufferBlow, your server becomes completely independent:

* **Your Data, Your Rules**: All messages, files, and user data are stored on hardware you control
* **No Third-Party Dependencies**: No reliance on Discord, Slack, or other companies' servers
* **Privacy by Design**: No algorithmic feeds, no data mining, no unnecessary tracking
* **Customization**: Configure server limits, moderation rules, and features to match your needs
* **Censorship Resistance**: Your community stays online as long as you maintain the server
* **Learning Opportunity**: Great way to experiment with distributed systems and modern web APIs

How the API Works in Practice
==============================

When you set up your PufferBlow server:

1. **The API starts running** on your chosen host and port (default: http://localhost:7575)

2. **Chat clients connect** to your API endpoints to:
   - Authenticate users and manage accounts
   - Create and join chat channels
   - Send and receive messages in real-time
   - Upload and download shared files

3. **Your community grows** as more users connect to your specific server instance

4. **You retain full control** over server settings, user data, and community guidelines

API Endpoints Overview
=======================

The API provides REST endpoints across several main categories:

**Authentication & Users** (``/api/v1/users``)
    User signup/login, profile management, avatar uploads, account settings

**Channels** (``/api/v1/channels``)
    Channel creation, listing, membership management, message loading

**Messaging** (``/api/v1/channels/{channel_id}``)
    Send messages, load message history, upload attachments

**File Management** (``/api/v1/cdn``)
    File uploads, downloads, organization, duplicate handling

**Server Administration** (``/api/v1/system``)
    Server settings, user management, analytics, maintenance

**Real-time Communication** (WebSocket)
    Live message delivery, typing indicators, presence updates

Connecting to Multiple Servers
==============================

One of PufferBlow's powerful features is **federation** (planned for future releases). While not yet implemented, the design allows users to:

* Maintain accounts on multiple independent servers
* Communicate seamlessly across server boundaries
* Discover new communities through server networks

This approach is inspired by the Fediverse (like Mastodon for social media) and represents the next evolution of online communities.

Getting Started with the API
============================

To start using the PufferBlow API, follow these steps:

1. **Set up your server** (see the :doc:`get_started` guide)
2. **Connect a client** (web client, mobile app, or custom integration)
3. **Configure your server settings** through the admin interface
4. **Invite users** and start building your community

The API is designed to be developer-friendly, with comprehensive documentation available at ``http://your-server:7575/docs`` when your server is running (using FastAPI's built-in OpenAPI/Swagger documentation).

Security & Privacy
==================

PufferBlow takes security seriously:

* **End-to-end Encryption**: Message contents are encrypted at rest and in transit
* **Strong Authentication**: Bcrypt password hashing and secure token management
* **Rate Limiting**: Protection against abuse and DDoS attacks
* **Input Validation**: Comprehensive validation of all user inputs
* **Audit Logging**: Complete tracking of user and system activities
* **IP Management**: Ability to block problematic IP addresses

Unlike centralized platforms, your self-hosted server gives you direct control over security measures and data handling practices.
