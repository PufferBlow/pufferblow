> **NOTE**: The project is still in development.
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->


# Introduction

The **pufferblow** is the official open-source server for **pufferblow**. Using it you can host your own server and create a community for you, your friends, and potentially others to join and spend wonderful times together. One of the key strengths of the **pufferblow** is its robust security measures. Being open-source and free to use, it ensures your privacy as it implements advanced encryption algorithms such as Blowfish and bcrypt for data hashing and encryption, making the **pufferblow** a secure choice for hosting your own server.
Unlike many other chat services that offer little control to the server owner, such as Discord and Guilded, **pufferblow** stands apart. With **pufferblow**, you have the ability to host your own server using **pufferblow** and customize it according to your preferences.

# Get Started

you get started on using pufferblow by following the instructions in the [documentation](https://pufferblow.github.io/pufferblow/)

# Recent Runtime Changes

## Fediversed client routing

The web client now treats the selected **home instance** as the authority for
federated operations and uses the ActivityPub-facing routes directly:

- `GET /.well-known/webfinger`
- `GET /ap/users/{user_id}`
- `GET /ap/users/{user_id}/outbox`
- `POST /api/v1/federation/follow`
- `POST /api/v1/dms/send`
- `GET /api/v1/dms/messages`

This keeps the client aligned with the fediverse model: authenticate against one
home instance, then resolve and interact with remote actors through that
instance.

## Instance health

The server now exposes health endpoints for both the Python control plane and
the attached media plane:

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/system/instance-health`

`/api/v1/system/instance-health` mirrors `media-sfu /healthz` when RTC is
configured, so operators can inspect one instance endpoint and still see media
plane status.

## CLI startup improvements

The CLI now defers heavy imports until the selected command actually runs. This
keeps `--help`, `version`, and other lightweight paths much faster than before.

There is also a small benchmark helper at
`scripts/benchmark_cli_startup.py` for measuring:

- `pufferblow --help`
- `pufferblow version`
- `pufferblow serve --help`
- `pufferblow storage --help`

# Instance Roles

Pufferblow now supports an instance-scoped role system backed by the server API. Roles are local to each home instance, and the client fetches them dynamically instead of relying on a fixed built-in role list.

For the longer operator/developer write-up, see ``docs/roles.rst`` in the
server documentation.

## Built-in roles

Each instance is seeded with these immutable system roles:

- `owner`
- `admin`
- `moderator`
- `user`

These built-in roles cannot be deleted or edited through the role-management API.

## Privilege model

Custom roles are composed from the existing privilege catalog. Current built-in privileges include:

- `create_users`
- `delete_users`
- `edit_users`
- `view_users`
- `reset_user_tokens`
- `create_channels`
- `delete_channels`
- `edit_channels`
- `manage_channel_users`
- `view_private_channels`
- `send_messages`
- `delete_messages`
- `edit_messages`
- `view_messages`
- `manage_server_settings`
- `manage_server_privileges`
- `manage_storage`
- `view_server_stats`
- `ban_users`
- `mute_users`
- `moderate_content`
- `view_audit_logs`
- `manage_blocked_ips`
- `upload_files`
- `delete_files`
- `view_files`
- `manage_background_tasks`

## API surface

Role management is exposed under `/api/v1/system`:

- `POST /api/v1/system/roles/list`
- `POST /api/v1/system/privileges/list`
- `POST /api/v1/system/roles`
- `PUT /api/v1/system/roles/{role_id}`
- `DELETE /api/v1/system/roles/{role_id}`
- `PUT /api/v1/system/users/{user_id}/roles`

Current behavior:

- any authenticated user can list instance roles
- only the instance owner can create, edit, delete, or assign roles
- the `owner` role cannot be assigned through the role editor
- built-in roles remain protected

## Client behavior

The control panel now asks the active home instance for its roles and privileges and renders them dynamically. Member role editing is no longer hardcoded to `owner/admin/member`.

Control-panel navigation is also privilege-aware, so accounts only see the
sections their resolved instance privileges actually allow.

Role management is now exposed as a dedicated `Roles` section in the control
panel instead of being buried inside member management.

## Privilege-backed routes

Custom roles now affect real server behavior. Examples:

- `create_channels` allows channel creation
- `delete_channels` allows channel deletion
- `manage_channel_users` allows private channel membership changes
- `view_private_channels` allows private channel visibility/access
- `delete_messages` allows moderation deletion of messages
- `manage_server_settings` allows server info/runtime-config updates
- `view_server_stats` allows control-panel metrics/overview access
- `view_audit_logs` allows recent-activity access
- `manage_blocked_ips` allows blocked-IP management
- `upload_files`, `view_files`, `delete_files`, and `manage_storage` back storage operations
- `manage_background_tasks` allows background-task status and on-demand execution

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://ramsy0dev.github.io"><img src="https://avatars.githubusercontent.com/u/86024158?v=4?s=100" width="100px;" alt="ramsy0dev"/><br /><sub><b>ramsy0dev</b></sub></a><br /><a href="https://github.com/PufferBlow/pufferblow/commits?author=ramsy0dev" title="Code">💻</a> <a href="#maintenance-ramsy0dev" title="Maintenance">🚧</a> <a href="https://github.com/PufferBlow/pufferblow/commits?author=ramsy0dev" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

# License

GPL-3.0
