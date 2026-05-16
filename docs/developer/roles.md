# Roles & privileges

Pufferblow has a **per-instance** role and privilege system.
Roles are not global across the fediverse — each instance owner
defines their own local roles, assigns them to local members,
and clients fetch the live catalog from the active instance
rather than relying on a hardcoded list.

## Role model

Every instance is seeded with four immutable **system roles**:

- `owner`
- `admin`
- `moderator`
- `user`

System roles can't be deleted or edited through the instance
role-management API. Owners can create additional **custom
roles** by composing privileges from the catalog below. Custom
roles remain local to the instance that created them.

## Privilege catalog

Roles are composed from these privilege identifiers:

### Users

- `create_users` · `delete_users` · `edit_users` · `view_users`
- `reset_user_tokens`
- `ban_users` · `mute_users`

### Channels

- `create_channels` · `delete_channels` · `edit_channels`
- `manage_channel_users` · `view_private_channels`

### Messages

- `send_messages` · `edit_messages` · `delete_messages` ·
  `view_messages`
- `moderate_content`

### Files & storage

- `upload_files` · `view_files` · `delete_files`
- `manage_storage`

### Server

- `manage_server_settings` · `manage_server_privileges`
- `view_server_stats` · `view_audit_logs`
- `manage_blocked_ips`
- `manage_background_tasks`

## How privileges resolve

When a client loads the current-user profile, the response
includes:

- `roles_ids` — the role IDs assigned to the user.
- `resolved_roles` — the full role records for each ID.
- `resolved_privileges` — the union of privileges granted by
  those roles.

This lets clients stay **dynamic**: a custom role created on
one instance appears in that instance's dashboard and control
panel without shipping a client update.

## Privilege-backed behavior

Custom roles affect real server behavior, not just UI badges:

| Privilege | What it actually unlocks |
| --- | --- |
| `create_channels` | Channel creation |
| `delete_channels` | Channel deletion |
| `edit_channels` | Channel rename, type change, settings |
| `manage_channel_users` | Private-channel membership changes |
| `view_private_channels` | Private-channel visibility and access |
| `delete_messages` | Moderation deletion |
| `manage_server_settings` | Server info + runtime-config changes |
| `view_server_stats` | Activity metrics + overview |
| `view_audit_logs` | Recent activity log access |
| `manage_blocked_ips` | List / block / unblock IPs |
| `upload_files` / `view_files` / `delete_files` / `manage_storage` | Storage operations |
| `manage_background_tasks` | Background-task status + on-demand runs |

## API surface

Role management lives under `/api/v1/system`:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/system/roles/list` | List instance roles |
| `POST /api/v1/system/privileges/list` | List the privilege catalog |
| `POST /api/v1/system/roles` | Create a custom role |
| `PUT /api/v1/system/roles/{role_id}` | Edit a custom role |
| `DELETE /api/v1/system/roles/{role_id}` | Delete a custom role |
| `PUT /api/v1/system/users/{user_id}/roles` | Assign roles to a user |

Current rules:

- Any authenticated user can list roles and the privilege
  catalog (the client needs this to render).
- Only the **instance owner** can create, edit, delete, or
  assign roles.
- The `owner` role cannot be assigned through the editor.
- System roles remain immutable.

## Client behavior

The control panel requests the role catalog and privilege
catalog directly from the active home instance, which means:

- Member role badges are dynamic.
- Role assignment is dynamic.
- The control panel exposes a dedicated **Roles** section for
  catalog and assignment work.
- Control-panel surfaces are **hidden** (not just disabled) when
  the current account lacks the matching privilege — same
  rationale as the home-instance dropdown menu: don't expose
  the privilege catalog to non-privileged users.

## Federation note

Roles follow the rest of Pufferblow's instance-first model:

- Authentication happens against one home instance at a time.
- Roles and privileges belong to that home instance.
- Remote actors flow through ActivityPub federation as usual.
- **Remote instances do not project their own role catalogs
  into your home instance** — a moderator on `example.org`
  isn't a moderator on `friend.network`.

This keeps moderation and access control local to whichever
instance owns the community data.
