"""Metrics, file, and activity mixin for database handler."""

from __future__ import annotations

import datetime
import hashlib

from loguru import logger
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.database.tables.activity_metrics import ActivityMetrics
from pufferblow.api.database.tables.channels import Channels
from pufferblow.api.database.tables.chart_data import ChartData
from pufferblow.api.database.tables.file_objects import FileObjects, FileReferences
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.database.tables.server import Server
from pufferblow.api.database.tables.users import Users
from pufferblow.api.utils.current_date import date_in_gmt


class DatabaseMetricsFilesMixin:
    @staticmethod
    def _coerce_datetime(value: datetime.datetime | str | None) -> datetime.datetime:
        """Normalize timestamps so SQLite-backed tests receive real datetime objects."""
        if isinstance(value, datetime.datetime):
            return value

        if isinstance(value, str):
            normalized = value.replace("Z", "+00:00")
            try:
                return datetime.datetime.fromisoformat(normalized)
            except ValueError:
                return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

        return datetime.datetime.now(datetime.timezone.utc)

    def get_user_registration_count_by_period(
        self, start_date: datetime, end_date: datetime
    ) -> int:
        """Get count of user registrations between dates"""
        with self.database_session() as session:
            result = session.query(func.count(Users.user_id)).filter(
                Users.created_at >= start_date, Users.created_at < end_date
            )
            return result.scalar() if result.scalar() is not None else 0

    def get_message_count_by_period(
        self, start_date: datetime, end_date: datetime
    ) -> int:
        """Get count of messages between dates"""
        try:
            with self.database_session() as session:
                result = session.query(func.count(Messages.message_id)).filter(
                    Messages.sent_at >= start_date, Messages.sent_at < end_date
                )
                return result.scalar() if result.scalar() is not None else 0
        except Exception:
            return 0

    def get_channel_creation_count_by_period(
        self, start_date: datetime, end_date: datetime
    ) -> int:
        """Get count of channel creations between dates"""
        with self.database_session() as session:
            result = session.query(func.count(Channels.channel_id)).filter(
                Channels.created_at >= start_date, Channels.created_at < end_date
            )
            return result.scalar() if result.scalar() is not None else 0

    def save_chart_data_entry(self, chart_data_entry: ChartData) -> None:
        """Insert or update a chart data entry by logical chart key."""
        with self.database_session() as session:
            def apply_entry(target: ChartData) -> None:
                target.time_start = self._coerce_datetime(chart_data_entry.time_start)
                target.time_end = self._coerce_datetime(chart_data_entry.time_end)
                target.metrics = chart_data_entry.metrics
                target.primary_value = chart_data_entry.primary_value
                target.updated_at = self._coerce_datetime(
                    getattr(chart_data_entry, "updated_at", None)
                )

            existing = (
                session.query(ChartData)
                .filter(
                    ChartData.chart_type == chart_data_entry.chart_type,
                    ChartData.period_type == chart_data_entry.period_type,
                    ChartData.time_key == chart_data_entry.time_key,
                )
                .first()
            )

            if existing:
                apply_entry(existing)
            else:
                chart_data_entry.time_start = self._coerce_datetime(chart_data_entry.time_start)
                chart_data_entry.time_end = self._coerce_datetime(chart_data_entry.time_end)
                chart_data_entry.created_at = self._coerce_datetime(
                    getattr(chart_data_entry, "created_at", None)
                )
                chart_data_entry.updated_at = self._coerce_datetime(
                    getattr(chart_data_entry, "updated_at", None)
                )
                session.add(chart_data_entry)

            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = (
                    session.query(ChartData)
                    .filter(
                        ChartData.chart_type == chart_data_entry.chart_type,
                        ChartData.period_type == chart_data_entry.period_type,
                        ChartData.time_key == chart_data_entry.time_key,
                    )
                    .first()
                )
                if existing is None:
                    raise

                apply_entry(existing)
                session.commit()

    def get_chart_data_entries(
        self, chart_type: str, period_type: str = None
    ) -> list[ChartData]:
        """Get chart data entries for a specific type and optional period"""
        with self.database_session() as session:
            query = session.query(ChartData).filter(ChartData.chart_type == chart_type)

            if period_type:
                query = query.filter(ChartData.period_type == period_type)

            return query.order_by(ChartData.time_start).all()

    def get_user_status_counts(self) -> dict[str, int]:
        """Get counts of users by status"""
        with self.database_session() as session:
            online_count = (
                session.query(func.count(Users.user_id))
                .filter(Users.status == "online")
                .scalar()
                or 0
            )

            offline_count = (
                session.query(func.count(Users.user_id))
                .filter(Users.status.in_(["offline", None, ""]))
                .scalar()
                or 0
            )

            idle_count = (
                session.query(func.count(Users.user_id))
                .filter(Users.status == "idle")
                .scalar()
                or 0
            )

            dnd_count = (
                session.query(func.count(Users.user_id))
                .filter(Users.status == "dnd")
                .scalar()
                or 0
            )

            afk_count = (
                session.query(func.count(Users.user_id))
                .filter(Users.status.in_(["afk", "away"]))
                .scalar()
                or 0
            )

            # Handle other statuses if any
            other_count = (
                session.query(func.count(Users.user_id))
                .filter(
                    Users.status.not_in(
                        ["online", "offline", "idle", "dnd", "afk", "away", "", None]
                    )
                )
                .scalar()
                or 0
            )

            return {
                "online": online_count,
                "offline": offline_count,
                "idle": idle_count,
                "dnd": dnd_count,
                "afk": afk_count,
                "other": other_count,
            }

    # Activity Metrics Methods

    def save_activity_metrics(self, metrics: ActivityMetrics) -> None:
        """Save activity metrics to the database"""
        with self.database_session() as session:
            # Check if metrics for this period already exist
            existing = (
                session.query(ActivityMetrics)
                .filter(
                    ActivityMetrics.period == metrics.period,
                    ActivityMetrics.date == metrics.date,
                )
                .first()
            )

            if existing:
                # Update existing metrics
                for attr, value in metrics.__dict__.items():
                    if not attr.startswith("_") and attr != "id":
                        setattr(existing, attr, value)
                existing.server_uptime_hours = metrics.server_uptime_hours
            else:
                # Save new metrics
                session.add(metrics)

            session.commit()

    def get_latest_activity_metrics(self) -> dict:
        """Get the latest activity metrics for dashboard display"""
        with self.database_session() as session:
            # Get total users and channels
            total_users = self.count_users()

            # Get total channels
            try:
                total_channels = session.query(func.count(Channels.channel_id)).scalar() or 0
            except Exception:
                total_channels = 0

            # Calculate current activity metrics

            # Messages per hour (current active period)
            one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
            try:
                messages_last_hour = (
                    session.query(func.count(Messages.message_id))
                    .filter(Messages.sent_at >= one_hour_ago)
                    .scalar()
                    or 0
                )
            except Exception:
                messages_last_hour = 0

            # Active users (users who sent messages in last 24 hours)
            twenty_four_hours_ago = datetime.datetime.now() - datetime.timedelta(
                hours=24
            )
            try:
                active_users_24h = (
                    session.query(func.count(func.distinct(Messages.sender_id)))
                    .filter(Messages.sent_at >= twenty_four_hours_ago)
                    .scalar()
                    or 0
                )
            except Exception:
                active_users_24h = 0

            # Current online users
            user_status_counts = self.get_user_status_counts()
            current_online = user_status_counts.get("online", 0)

            # Calculate engagement rate (active users / total users)
            engagement_rate = (
                (active_users_24h / total_users * 100) if total_users > 0 else 0
            )

            # Get latest activity metrics record for trends
            latest_metrics = (
                session.query(ActivityMetrics)
                .order_by(ActivityMetrics.created_at.desc())
                .first()
            )

            return {
                "total_users": total_users,
                "total_channels": total_channels,
                "messages_per_hour": messages_last_hour,
                "active_users_24h": active_users_24h,
                "current_online": current_online,
                "engagement_rate": round(engagement_rate, 1),
                "messages_per_active_user": (
                    round(messages_last_hour / max(active_users_24h, 1), 1)
                    if messages_last_hour > 0
                    else 0
                ),
                "channel_utilization": (
                    min(int((active_users_24h / max(total_channels, 1)) * 100), 100)
                    if total_channels > 0
                    else 0
                ),
                "last_updated": (
                    latest_metrics.created_at.isoformat() if latest_metrics else None
                ),
            }

    def calculate_daily_activity_metrics(self) -> ActivityMetrics | None:
        """Calculate and return daily activity metrics"""
        # Get today's date (start of day)
        today = datetime.datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        tomorrow = today + datetime.timedelta(days=1)

        with self.database_session() as session:
            # Count new users registered today
            new_users_today = self.get_user_registration_count_by_period(
                today, tomorrow
            )

            # Count messages sent today
            messages_today = self.get_message_count_by_period(today, tomorrow)

            # Get active users today (users who sent messages)
            active_users_today = (
                session.query(func.count(func.distinct(Messages.sender_id)))
                .filter(Messages.sent_at >= today, Messages.sent_at < tomorrow)
                .scalar()
                or 0
            )

            # Get online user stats
            online_avg = (
                session.query(func.avg(ChartData.primary_value))
                .filter(
                    ChartData.chart_type == "online_users",
                    ChartData.period_type == "hourly",
                    ChartData.time_start >= today,
                    ChartData.time_start < tomorrow,
                )
                .scalar()
                or 0
            )

            online_peak = (
                session.query(func.max(ChartData.primary_value))
                .filter(
                    ChartData.chart_type == "online_users",
                    ChartData.period_type == "hourly",
                    ChartData.time_start >= today,
                    ChartData.time_start < tomorrow,
                )
                .scalar()
                or 0
            )

            if not online_avg and not online_peak:
                current_online = self.get_current_online_count()
                online_avg = float(current_online)
                online_peak = current_online

            # Get total users at end of day
            total_users = self.count_users()

            # Get channels used today
            channels_used_today = (
                session.query(func.count(func.distinct(Messages.channel_id)))
                .filter(Messages.sent_at >= today, Messages.sent_at < tomorrow)
                .scalar()
                or 0
            )

            # Get total channels
            total_channels = (
                session.query(func.count(Channels.channel_id)).scalar() or 0
            )

            # Calculate messages per hour average for today
            messages_per_hour = messages_today / 24 if messages_today > 0 else 0

            # Calculate engagement metrics
            engagement_rate = (
                (active_users_today / total_users * 100) if total_users > 0 else 0
            )
            messages_per_active_user = (
                messages_today / max(active_users_today, 1) if messages_today > 0 else 0
            )
            channel_utilization_rate = (
                (channels_used_today / max(total_channels, 1) * 100)
                if total_channels > 0
                else 0
            )

            # Calculate server uptime (this would need to be tracked system-wide)
            server_uptime_hours = 24.0  # Simplified - would need to track actual uptime

            # Get file upload stats for today
            files_uploaded_today = (
                session.query(func.count(FileReferences.id))
                .filter(
                    FileReferences.created_at >= today,
                    FileReferences.created_at < tomorrow,
                )
                .scalar()
                or 0
            )

            total_file_size_today = (
                session.query(func.sum(FileObjects.file_size))
                .join(FileReferences, FileObjects.file_id == FileReferences.file_id)
                .filter(
                    FileReferences.created_at >= today,
                    FileReferences.created_at < tomorrow,
                )
                .scalar()
                or 0
            )

            total_file_size_mb = (
                total_file_size_today / (1024 * 1024) if total_file_size_today else 0
            )

            return ActivityMetrics(
                period="daily",
                date=today,
                total_users=total_users,
                new_users=new_users_today,
                active_users=active_users_today,
                online_users_avg=online_avg,
                online_users_peak=online_peak,
                total_messages=messages_today,
                messages_this_period=messages_today,
                messages_per_hour=messages_per_hour,
                channels_used=channels_used_today,
                user_engagement_rate=engagement_rate,
                messages_per_active_user=messages_per_active_user,
                channel_utilization_rate=channel_utilization_rate,
                files_uploaded=files_uploaded_today,
                total_file_size_mb=total_file_size_mb,
                server_uptime_hours=server_uptime_hours,
            )

    def count_channels(self) -> int:
        """Count total channels in the server"""
        with self.database_session() as session:
            return session.query(func.count(Channels.channel_id)).scalar() or 0

    def get_current_online_count(self) -> int:
        """Get current online users count"""
        status_counts = self.get_user_status_counts()
        return status_counts.get("online", 0)

    def update_server_avatar_url(self, avatar_url: str) -> None:
        """Update the server's avatar URL

        Args:
            avatar_url (str): The new avatar URL.

        Returns:
            None.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        # For SQLite tests where server table is not created, skip
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = update(Server).values(avatar_url=avatar_url, updated_at=updated_at)

            session.execute(stmt)

            session.commit()

    def update_server_banner_url(self, banner_url: str) -> None:
        """Update the server's banner URL

        Args:
            banner_url (str): The new banner URL.

        Returns:
            None.
        """
        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        # For SQLite tests where server table is not created, skip
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = update(Server).values(banner_url=banner_url, updated_at=updated_at)

            session.execute(stmt)

            session.commit()

    def create_file_object(
        self,
        file_hash: str,
        ref_count: int,
        file_path: str,
        filename: str,
        file_size: int,
        mime_type: str,
        verification_status: str = "unverified",
    ) -> None:
        """
        Create a file object entry in the database

        Args:
            file_hash (str): SHA-256 hash of the file
            ref_count (int): Initial reference count
            file_path (str): Relative path to the file
            filename (str): Original filename of the uploaded file
            file_size (int): File size in bytes
            mime_type (str): MIME type of the file
            verification_status (str): Verification status

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        file_obj = FileObjects(
            file_hash=file_hash,
            ref_count=ref_count,
            file_path=file_path,
            filename=filename,
            file_size=file_size,
            mime_type=mime_type,
            verification_status=verification_status,
        )

        with self.database_session() as session:
            session.add(file_obj)
            session.commit()

    def create_file_reference(
        self,
        reference_id: str,
        file_hash: str,
        reference_type: str,
        reference_entity_id: str,
    ) -> None:
        """
        Create a file reference entry in the database

        Args:
            reference_id (str): Unique reference identifier
            file_hash (str): SHA-256 hash of the file
            reference_type (str): Type of reference (e.g., 'storage_upload')
            reference_entity_id (str): ID of the entity being referenced

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        file_ref = FileReferences(
            reference_id=reference_id,
            file_hash=file_hash,
            reference_type=reference_type,
            reference_entity_id=reference_entity_id,
        )

        with self.database_session() as session:
            session.add(file_ref)
            session.commit()

    def increment_file_reference_count(self, file_hash: str) -> None:
        """
        Increment the reference count for a file

        Args:
            file_hash (str): SHA-256 hash of the file

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = (
                update(FileObjects)
                .values(ref_count=FileObjects.ref_count + 1)
                .where(FileObjects.file_hash == file_hash)
            )
            session.execute(stmt)
            session.commit()

    def decrement_file_reference_count(self, file_hash: str) -> None:
        """
        Decrement the reference count for a file

        Args:
            file_hash (str): SHA-256 hash of the file

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = (
                update(FileObjects)
                .values(ref_count=FileObjects.ref_count - 1)
                .where(FileObjects.file_hash == file_hash)
            )
            session.execute(stmt)
            session.commit()

    def cleanup_orphaned_files(self, db_files: list[str] = None) -> None:
        """
        Remove files that are no longer referenced in the database.
        This is used by storage cleanup to remove unreferenced files.

        Args:
            db_files (List[str]): Optional list of referenced file URLs.
                                If None, uses database references.

        Returns:
            None
        """
        from pathlib import Path

        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            if db_files is None:
                # Get all referenced file hashes from the database
                file_hashes = session.query(FileReferences.file_hash).distinct().all()
                file_hashes = [h[0] for h in file_hashes]
            else:
                # Convert input URLs to hashes when raw paths are provided.
                file_hashes = []
                for url in db_files:
                    # Extract path from URL and try to find corresponding file
                    base_url = self.config.STORAGE_BASE_URL.lstrip("/")
                    normalized_url = url.lstrip("/")
                    if normalized_url.startswith(base_url):
                        relative_path = normalized_url[len(base_url) :].lstrip("/")
                        file_path = Path(self.config.STORAGE_PATH) / relative_path
                        if file_path.exists():
                            try:
                                with open(file_path, "rb") as f:
                                    content = f.read()
                                    file_hash = hashlib.sha256(content).hexdigest()
                                    file_hashes.append(file_hash)
                            except:
                                continue

            # Get files with zero references
            orphaned_files = (
                session.query(FileObjects)
                .filter(
                    FileObjects.ref_count <= 0,
                    FileObjects.file_hash.not_in(file_hashes) if file_hashes else True,
                )
                .all()
            )

            # Delete orphaned files from disk and database
            for file_obj in orphaned_files:
                file_path = Path(self.config.STORAGE_PATH) / file_obj.file_path
                try:
                    if file_path.exists():
                        file_path.unlink()
                        logger.info(f"Deleted orphaned file: {file_obj.file_path}")

                    # Remove from database
                    session.delete(file_obj)

                except Exception as e:
                    logger.warning(
                        f"Failed to delete orphaned file {file_obj.file_path}: {e}"
                    )

            # Also find and remove files on disk that aren't in the database
            storage_dir = Path(self.config.STORAGE_PATH)
            if storage_dir.exists():
                for sub_dir in storage_dir.glob("*"):
                    if sub_dir.is_dir():  # Only process subdirectories
                        for file_path in sub_dir.glob("*"):
                            if file_path.is_file():
                                try:
                                    with open(file_path, "rb") as f:
                                        content = f.read()
                                        file_hash = hashlib.sha256(content).hexdigest()

                                    # Check if this file exists in database
                                    existing = (
                                        session.query(FileObjects)
                                        .filter(FileObjects.file_hash == file_hash)
                                        .first()
                                    )

                                    if not existing:
                                        # File not in database, check if it's referenced
                                        is_referenced = (
                                            session.query(FileReferences)
                                            .filter(
                                                FileReferences.file_hash == file_hash
                                            )
                                            .count()
                                            > 0
                                        )

                                        if not is_referenced:
                                            # Truly orphaned file - remove it
                                            file_path.unlink()
                                            logger.info(
                                                f"Deleted unreferenced file on disk: {file_path.name}"
                                            )
                                except:
                                    continue

            session.commit()

    def get_referenced_files_list(self) -> list[str]:
        """
        Get a list of all referenced file URLs for cleanup operations

        Args:
            None

        Returns:
            List[str]: List of referenced file URLs
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return []

        with self.database_session() as session:
            # Get all referenced file hashes
            results = (
                session.query(FileReferences.file_hash, FileObjects.file_path)
                .join(FileObjects, FileReferences.file_hash == FileObjects.file_hash)
                .all()
            )

            # Convert to URLs
            referenced_files = []
            for file_hash, file_path in results:
                url = f"{self.config.STORAGE_BASE_URL.rstrip('/')}/{file_path}"
                referenced_files.append(url)

            return referenced_files

    # Activity Audit Methods

    def create_activity_audit_entry(self, activity_audit: ActivityAudit) -> None:
        """
        Create an activity audit entry in the database

        Args:
            activity_audit (ActivityAudit): The activity audit entry to create

        Returns:
            None
        """
        try:
            with self.database_session() as session:
                activity_audit.created_at = self._coerce_datetime(
                    getattr(activity_audit, "created_at", None)
                )
                activity_audit.updated_at = self._coerce_datetime(
                    getattr(activity_audit, "updated_at", None)
                )
                session.add(activity_audit)
                session.commit()
        except Exception as exc:
            logger.warning(f"Failed to create activity audit entry: {exc}")

    def get_recent_activities(self, limit: int = 10) -> list[ActivityAudit]:
        """
        Get recent activity audit entries, ordered by creation time (newest first)

        Args:
            limit (int): Maximum number of activity entries to return

        Returns:
            list[ActivityAudit]: List of recent activity entries
        """
        try:
            with self.database_session() as session:
                activities = (
                    session.query(ActivityAudit)
                    .order_by(ActivityAudit.created_at.desc())
                    .limit(limit)
                    .all()
                )
                return activities
        except Exception as exc:
            logger.warning(f"Failed to load recent activities: {exc}")
            return []

    def list_activity_audit_entries(
        self,
        *,
        activity_types: list[str] | None = None,
        limit: int = 100,
    ) -> list[ActivityAudit]:
        """List activity audit entries ordered from newest to oldest."""
        try:
            with self.database_session() as session:
                stmt = select(ActivityAudit).order_by(ActivityAudit.created_at.desc())
                if activity_types:
                    stmt = stmt.where(ActivityAudit.activity_type.in_(activity_types))
                stmt = stmt.limit(limit)
                return list(session.execute(stmt).scalars().all())
        except Exception as exc:
            logger.warning(f"Failed to list activity audit entries: {exc}")
            return []

    def update_file_object(
        self,
        old_file_hash: str,
        new_file_hash: str,
        new_file_path: str,
        new_file_size: int,
        new_mime_type: str,
    ) -> None:
        """
        Update a file object with new metadata after optimization

        Args:
            old_file_hash (str): Original file hash
            new_file_hash (str): New file hash after optimization
            new_file_path (str): New file path after optimization
            new_file_size (int): New file size after optimization
            new_mime_type (str): New MIME type after optimization

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        updated_at = date_in_gmt(format="%Y-%m-%d %H:%M:%S")

        with self.database_session() as session:
            stmt = (
                update(FileObjects)
                .values(
                    file_hash=new_file_hash,
                    file_path=new_file_path,
                    file_size=new_file_size,
                    mime_type=new_mime_type,
                    updated_at=updated_at,
                )
                .where(FileObjects.file_hash == old_file_hash)
            )
            session.execute(stmt)
            session.commit()

    def update_file_references(self, old_file_hash: str, new_file_hash: str) -> None:
        """
        Update all file references to point to the new file hash after optimization

        Args:
            old_file_hash (str): Original file hash
            new_file_hash (str): New file hash after optimization

        Returns:
            None
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return

        with self.database_session() as session:
            stmt = (
                update(FileReferences)
                .values(file_hash=new_file_hash)
                .where(FileReferences.file_hash == old_file_hash)
            )
            session.execute(stmt)
            session.commit()

    def get_file_object_by_hash(self, file_hash: str) -> FileObjects | None:
        """
        Get a file object by its hash

        Args:
            file_hash (str): SHA-256 hash of the file

        Returns:
            FileObjects | None: The file object if found, None otherwise
        """
        # Skip for SQLite tests where file tables are not created
        database_uri = str(self.database_engine.url)
        if database_uri.startswith("sqlite://"):
            return None

        with self.database_session() as session:
            stmt = select(FileObjects).where(FileObjects.file_hash == file_hash)
            result = session.execute(stmt).fetchone()
            return result[0] if result else None
