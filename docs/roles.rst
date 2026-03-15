====================
Instance Role System
====================

Pufferblow supports a role and privilege system that is scoped to each home
instance. Roles are not global across the fediverse. Each instance owner defines
its own local roles, assigns them to local members, and the client fetches the
live role catalog from the active instance instead of relying on a hardcoded
list.

Role Model
==========

Every instance is seeded with immutable system roles:

- ``owner``
- ``admin``
- ``moderator``
- ``user``

The built-in roles are protected. They cannot be deleted or edited through the
instance role-management API.

Owners can create additional custom roles from the privilege catalog. Those
roles remain local to the instance that created them.

Privilege Catalog
=================

Roles are composed from existing privilege identifiers. The current catalog
includes:

- ``create_users``
- ``delete_users``
- ``edit_users``
- ``view_users``
- ``reset_user_tokens``
- ``create_channels``
- ``delete_channels``
- ``edit_channels``
- ``manage_channel_users``
- ``view_private_channels``
- ``send_messages``
- ``delete_messages``
- ``edit_messages``
- ``view_messages``
- ``manage_server_settings``
- ``manage_server_privileges``
- ``manage_storage``
- ``view_server_stats``
- ``ban_users``
- ``mute_users``
- ``moderate_content``
- ``view_audit_logs``
- ``manage_blocked_ips``
- ``upload_files``
- ``delete_files``
- ``view_files``
- ``manage_background_tasks``

Privilege Resolution
====================

When a client loads the current user profile, the API now includes:

- ``roles_ids``
- ``resolved_roles``
- ``resolved_privileges``

This allows the client to stay dynamic. A custom role created on one instance
appears in the dashboard and control panel without shipping a client update.

API Endpoints
=============

Role management lives under ``/api/v1/system``:

- ``POST /api/v1/system/roles/list``
- ``POST /api/v1/system/privileges/list``
- ``POST /api/v1/system/roles``
- ``PUT /api/v1/system/roles/{role_id}``
- ``DELETE /api/v1/system/roles/{role_id}``
- ``PUT /api/v1/system/users/{user_id}/roles``

Current rules:

- any authenticated user can list roles and privileges
- only the instance owner can create, edit, delete, or assign roles
- the ``owner`` role cannot be assigned through the editor
- system roles remain immutable

Client Behavior
===============

The control panel now requests the role catalog and privilege catalog directly
from the active home instance.

That means:

- member role badges are dynamic
- role assignment is dynamic
- the control panel exposes a dedicated ``Roles`` section for role catalog and
  member assignment work
- control-panel surfaces can be hidden when the current account lacks the
  matching privilege on that instance

Privilege-Backed Behavior
=========================

Custom roles now affect real server behavior. Examples:

- ``create_channels`` allows channel creation
- ``delete_channels`` allows channel deletion
- ``manage_channel_users`` allows private-channel membership changes
- ``view_private_channels`` allows private-channel visibility and access
- ``delete_messages`` allows moderation deletion of messages
- ``manage_server_settings`` allows server info and runtime-config changes
- ``view_server_stats`` allows access to activity metrics and overview data
- ``view_audit_logs`` allows access to recent activity logs
- ``manage_blocked_ips`` allows blocked IP list, block, and unblock operations
- ``upload_files``, ``view_files``, ``delete_files``, and ``manage_storage`` back
  storage operations
- ``manage_background_tasks`` allows background task status and on-demand task execution

Fediversed Architecture Notes
=============================

The role system follows the current fediversed Pufferblow model:

- authentication happens against one home instance at a time
- roles and privileges belong to that home instance
- remote actors are still handled through federation and ActivityPub flows
- remote instances do not project their own local role catalogs into your home
  instance

This keeps moderation and access control local to the instance that owns the
community data.
