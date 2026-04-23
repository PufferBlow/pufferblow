"""Server media upload routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile

from .shared import (
    delete_previous_storage_file,
    log_activity,
    parse_upload_auth_form,
    require_component,
    require_privilege,
)

router = APIRouter()


async def _upload_server_media(
    *,
    auth_token: str,
    upload: UploadFile,
    field_name: str,
    force_category: str,
    reference_type: str,
) -> dict:
    """Upload avatar/banner media and update server row."""
    user_id = require_privilege(auth_token, "manage_server_settings")
    database_handler = require_component("database_handler")
    storage_manager = require_component("storage_manager")
    current_server = database_handler.get_server()
    if current_server is None:
        raise HTTPException(
            status_code=404,
            detail="Server instance has not been initialized yet.",
        )

    existing_url = getattr(current_server, field_name)
    if existing_url:
        await delete_previous_storage_file(existing_url)

    try:
        storage_url, _, _, _, _ = await storage_manager.upload_file(
            file=upload,
            user_id=user_id,
            reference_type=reference_type,
            force_category=force_category,
            check_duplicates=False,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if field_name == "avatar_url":
        database_handler.update_server_avatar_url(storage_url)
        log_activity(
            activity_type="server_avatar_updated",
            user_id=user_id,
            title="Server avatar updated",
            description=f"Server avatar was updated by user {user_id}",
            metadata={"avatar_url": storage_url, "updated_by": user_id},
        )
        return {
            "status_code": 201,
            "message": "Server avatar uploaded successfully",
            "avatar_url": storage_url,
        }

    database_handler.update_server_banner_url(storage_url)
    log_activity(
        activity_type="server_banner_updated",
        user_id=user_id,
        title="Server banner updated",
        description=f"Server banner was updated by user {user_id}",
        metadata={"banner_url": storage_url, "updated_by": user_id},
    )
    return {
        "status_code": 201,
        "message": "Server banner uploaded successfully",
        "banner_url": storage_url,
    }


@router.post("/api/v1/system/upload-avatar", status_code=201)
async def upload_server_avatar_route(
    form_data=Depends(parse_upload_auth_form),
    avatar: UploadFile = Form(..., description="Server avatar image file"),
):
    """Upload server avatar."""
    return await _upload_server_media(
        auth_token=form_data.auth_token,
        upload=avatar,
        field_name="avatar_url",
        force_category="avatars",
        reference_type="server_avatar",
    )


@router.post("/api/v1/system/upload-banner", status_code=201)
async def upload_server_banner_route(
    form_data=Depends(parse_upload_auth_form),
    banner: UploadFile = Form(..., description="Server banner image file"),
):
    """Upload server banner."""
    return await _upload_server_media(
        auth_token=form_data.auth_token,
        upload=banner,
        field_name="banner_url",
        force_category="banners",
        reference_type="server_banner",
    )
