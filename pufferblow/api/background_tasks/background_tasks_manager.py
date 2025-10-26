import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, Callable, Optional, List
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import uuid
import httpx
import json

from loguru import logger

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.cdn.cdn_manager import CDNManager
from pufferblow.api.models.config_model import Config

# Database table models
from pufferblow.api.database.tables.users import Users
from pufferblow.api.database.tables.channels import Channels
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.database.tables.chart_data import ChartData


class BackgroundTasksManager:
    """
    Background Tasks Manager for scheduling and running background tasks
    that need to be executed periodically or on-demand.
    """

    def __init__(
        self,
        database_handler: DatabaseHandler,
        cdn_manager: CDNManager,
        config: Config
    ):
        self.database_handler = database_handler
        self.cdn_manager = cdn_manager
        self.config = config

        # Task registry
        self.tasks: Dict[str, Dict[str, Any]] = {}

        # Executor for CPU-intensive tasks
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bg-task")

        # Running tasks
        self.running_tasks: Dict[str, asyncio.Task] = {}

        # Task statistics
        self.task_stats: Dict[str, Dict[str, Any]] = {}

        # Historical data for charts
        self.chart_data: Dict[str, Dict[str, Any]] = {}

        self.logger = logging.getLogger(__name__)

        # Initialize chart data structures
        self._initialize_chart_data()

    def register_task(
        self,
        task_id: str,
        task_func: Callable,
        interval_minutes: Optional[int] = None,
        interval_hours: Optional[int] = None,
        enabled: bool = True,
        **kwargs
    ):
        """
        Register a background task

        Args:
            task_id: Unique task identifier
            task_func: Function to execute
            interval_minutes: Run every X minutes
            interval_hours: Run every X hours
            enabled: Whether task is enabled
            **kwargs: Additional task parameters
        """
        self.tasks[task_id] = {
            'id': task_id,
            'func': task_func,
            'interval_minutes': interval_minutes,
            'interval_hours': interval_hours,
            'enabled': enabled,
            'kwargs': kwargs,
            'next_run': datetime.now() + timedelta(
                minutes=interval_minutes or 0,
                hours=interval_hours or 0
            ) if (interval_minutes or interval_hours) else None
        }

        self.task_stats[task_id] = {
            'runs': 0,
            'errors': 0,
            'last_run': None,
            'last_error': None,
            'total_runtime': 0.0
        }

        logger.info(f"Registered background task: {task_id}")

    async def start_scheduler(self):
        """Start the background task scheduler"""
        logger.info("Starting background tasks scheduler")

        while True:
            try:
                await self._run_scheduled_tasks()
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Scheduler error: {str(e)}")
                await asyncio.sleep(60)

    async def _run_scheduled_tasks(self):
        """Run tasks that are due"""
        now = datetime.now()

        for task_id, task_info in self.tasks.items():
            if not task_info['enabled']:
                continue

            if task_info['next_run'] and now >= task_info['next_run']:
                try:
                    await self.run_task(task_id)

                    # Schedule next run
                    interval = timedelta(
                        minutes=task_info['interval_minutes'] or 0,
                        hours=task_info['interval_hours'] or 0
                    )
                    task_info['next_run'] = now + interval

                except Exception as e:
                    logger.error(f"Failed to run scheduled task {task_id}: {str(e)}")

    async def run_task(self, task_id: str) -> bool:
        """
        Execute a background task

        Args:
            task_id: Task identifier

        Returns:
            True if successful, False otherwise
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return False

        task_info = self.tasks[task_id]

        # Prevent concurrent runs of the same task
        if task_id in self.running_tasks:
            logger.warning(f"Task {task_id} is already running")
            return True

        start_time = datetime.now()

        try:
            logger.info(f"Starting background task: {task_id}")

            # Create task
            task = asyncio.create_task(
                self._execute_task_func(
                    task_info['func'],
                    **task_info['kwargs']
                )
            )

            self.running_tasks[task_id] = task

            # Wait for completion
            await task

            # Update statistics
            self.task_stats[task_id]['runs'] += 1
            self.task_stats[task_id]['last_run'] = start_time
            duration = (datetime.now() - start_time).total_seconds()
            self.task_stats[task_id]['total_runtime'] += duration

            logger.info(f"Completed background task: {task_id}")
            return True

        except Exception as e:
            logger.error(f"Background task {task_id} failed: {str(e)}")
            self.task_stats[task_id]['errors'] += 1
            self.task_stats[task_id]['last_error'] = str(e)
            return False

        finally:
            # Clean up
            if task_id in self.running_tasks:
                del self.running_tasks[task_id]

    async def _execute_task_func(self, func: Callable, **kwargs):
        """Execute task function, handling async/sync functions"""
        if asyncio.iscoroutinefunction(func):
            await func(**kwargs)
        else:
            # Run CPU-intensive tasks in thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, func, **kwargs)

    def get_task_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered tasks"""
        status = {}

        for task_id, task_info in self.tasks.items():
            status[task_id] = {
                'registered': True,
                'enabled': task_info['enabled'],
                'next_run': task_info['next_run'].isoformat() if task_info['next_run'] else None,
                'running': task_id in self.running_tasks,
                **self.task_stats[task_id]
            }

        return status

    def enable_task(self, task_id: str) -> bool:
        """Enable a task"""
        if task_id in self.tasks:
            self.tasks[task_id]['enabled'] = True
            logger.info(f"Enabled background task: {task_id}")
            return True
        return False

    def disable_task(self, task_id: str) -> bool:
        """Disable a task"""
        if task_id in self.tasks:
            self.tasks[task_id]['enabled'] = False
            logger.info(f"Disabled background task: {task_id}")
            return True
        return False

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        if task_id in self.running_tasks:
            task = self.running_tasks[task_id]
            task.cancel()
            del self.running_tasks[task_id]
            logger.info(f"Cancelled background task: {task_id}")
            return True
        return False

    # Specific task implementations

    async def cleanup_cdn_orphaned_files(self):
        """Clean up orphaned files in CDN storage"""
        logger.info("Starting CDN cleanup task")

        try:
            # Get all referenced file URLs from database
            referenced_urls = await self._get_referenced_file_urls()

            # Get all file categories from CDN manager
            all_categories = [
                'files', 'images', 'avatars', 'banners', 'gifs', 'stickers',
                'videos', 'audio', 'documents', 'config'
            ]

            total_deleted = 0

            for category in all_categories:
                # Get all files in directory
                directory_files = self._get_directory_files(category)

                # Filter to keep only referenced files
                subdir_deleted = self.cdn_manager.cleanup_orphaned_files(directory_files, category)
                total_deleted += subdir_deleted or 0

            logger.info(f"CDN cleanup completed. Deleted {total_deleted} orphaned files from {len(all_categories)} categories")

        except Exception as e:
            logger.error(f"CDN cleanup failed: {str(e)}")
            raise

    async def _get_referenced_file_urls(self) -> List[str]:
        """Get all file URLs referenced in the database"""
        try:
            # Get all user avatars and banners
            referenced_urls = []

            # For now, we'll focus on user avatars/banners only
            # This is a simplified implementation - in a full implementation,
            # we'd add a method to the database handler to systematically
            # collect all referenced files from users, messages, etc.

            # Get user avatars and banners via direct query
            with self.database_handler.database_session() as session:
                from sqlalchemy import select
                result = session.execute(select(Users.avatar, Users.banner))
                for avatar, banner in result:
                    if avatar:
                        referenced_urls.append(avatar)
                    if banner:
                        referenced_urls.append(banner)

            # Could add more sources like message attachments, etc. in future
            return referenced_urls

        except Exception as e:
            logger.error(f"Failed to get referenced file URLs: {str(e)}")
            return []

    def _get_directory_files(self, subdirectory: str) -> List[str]:
        """Get all file URLs in a CDN subdirectory"""
        try:
            from pathlib import Path
            sub_dir = Path(self.config.CDN_STORAGE_PATH) / subdirectory

            if not sub_dir.exists():
                return []

            files = []
            for file_path in sub_dir.glob("*"):
                if file_path.is_file():
                    files.append(f"{self.config.CDN_BASE_URL}/{subdirectory}/{file_path.name}")

            return files

        except Exception as e:
            logger.error(f"Failed to get directory files for {subdirectory}: {str(e)}")
            return []

    def cleanup_expired_auth_tokens(self):
        """Clean up expired authentication tokens"""
        logger.info("Starting auth token cleanup task")

        try:
            # This would require a method in database_handler to clean up expired tokens
            # For now, just log that it's running
            logger.info("Auth token cleanup completed (not yet implemented)")

        except Exception as e:
            logger.error(f"Auth token cleanup failed: {str(e)}")
            raise

    def update_activity_metrics(self):
        """Update activity metrics for dashboard display"""
        logger.info("Starting activity metrics update")

        try:
            # Calculate daily activity metrics
            metrics = self.database_handler.calculate_daily_activity_metrics()

            if metrics is not None:
                # Save activity metrics to database
                self.database_handler.save_activity_metrics(metrics)

                # Log summary
                logger.info(f"Activity metrics updated successfully")
            else:
                logger.warning("No activity metrics calculated (possibly no data)")

        except Exception as e:
            logger.error(f"Activity metrics update failed: {str(e)}")
            raise

    def update_server_statistics(self):
        """Update server statistics/usage metrics"""
        logger.info("Starting server statistics update")

        try:
            # Calculate server statistics
            stats = self._calculate_server_statistics()

            # Store the statistics
            self.server_stats = stats

            # Log summary
            logger.info(f"Server statistics updated: {len(stats['channels'])} channels, {stats['users']['total']} total users, {stats['users']['online']} online")

        except Exception as e:
            logger.error(f"Server statistics update failed: {str(e)}")
            raise

    def _calculate_server_statistics(self) -> Dict[str, Any]:
        """Calculate comprehensive server statistics"""
        try:
            stats = {
                'timestamp': datetime.now(),
                'users': {},
                'channels': {},
                'messages': {},
                'system': {}
            }

            # User statistics
            users_stats = self._calculate_user_statistics()
            stats['users'] = users_stats

            # Channel statistics
            channels_stats = self._calculate_channel_statistics()
            stats['channels'] = channels_stats

            # Message statistics
            messages_stats = self._calculate_message_statistics()
            stats['messages'] = messages_stats

            # System statistics
            stats['system'] = {
                'uptime': None,  # Could be calculated from server start time
                'last_updated': datetime.now().isoformat()
            }

            return stats

        except Exception as e:
            logger.error(f"Failed to calculate server statistics: {str(e)}")
            raise

    def _calculate_user_statistics(self) -> Dict[str, Any]:
        """Calculate user-related statistics"""
        try:
            with self.database_handler.database_session() as session:
                from sqlalchemy import select, func

                # Total users
                total_users = session.execute(
                    select(func.count()).select_from(Users)
                ).scalar()

                # Online users (status = 'online')
                online_users = session.execute(
                    select(func.count()).select_from(Users).where(Users.status == 'online')
                ).scalar()

                # Recently active users (last seen within 24 hours)
                yesterday = datetime.now() - timedelta(days=1)
                recent_users = session.execute(
                    select(func.count()).select_from(Users).where(
                        Users.last_seen >= yesterday
                    )
                ).scalar()

                # New users in past week
                week_ago = datetime.now() - timedelta(days=7)
                new_users_week = session.execute(
                    select(func.count()).select_from(Users).where(
                        Users.created_at >= week_ago
                    )
                ).scalar()

                # New users in past month
                month_ago = datetime.now() - timedelta(days=30)
                new_users_month = session.execute(
                    select(func.count()).select_from(Users).where(
                        Users.created_at >= month_ago
                    )
                ).scalar()

            return {
                'total': total_users or 0,
                'online': online_users or 0,
                'recently_active': recent_users or 0,
                'new_this_week': new_users_week or 0,
                'new_this_month': new_users_month or 0
            }

        except Exception as e:
            logger.error(f"Failed to calculate user statistics: {str(e)}")
            return {
                'total': 0,
                'online': 0,
                'recently_active': 0,
                'new_this_week': 0,
                'new_this_month': 0
            }

    def _calculate_channel_statistics(self) -> Dict[str, Any]:
        """Calculate channel-related statistics"""
        try:
            with self.database_handler.database_session() as session:
                from sqlalchemy import select, func

                # Total channels
                total_channels = session.execute(
                    select(func.count()).select_from(Channels)
                ).scalar()

                # Public vs private channels
                public_channels = session.execute(
                    select(func.count()).select_from(Channels).where(
                        Channels.is_private == False
                    )
                ).scalar()

                private_channels = session.execute(
                    select(func.count()).select_from(Channels).where(
                        Channels.is_private == True
                    )
                ).scalar()

                # New channels in past week
                week_ago = datetime.now() - timedelta(days=7)
                new_channels_week = session.execute(
                    select(func.count()).select_from(Channels).where(
                        Channels.created_at >= week_ago
                    )
                ).scalar()

                # New channels in past month
                month_ago = datetime.now() - timedelta(days=30)
                new_channels_month = session.execute(
                    select(func.count()).select_from(Channels).where(
                        Channels.created_at >= month_ago
                    )
                ).scalar()

            return {
                'total': total_channels or 0,
                'public': public_channels or 0,
                'private': private_channels or 0,
                'new_this_week': new_channels_week or 0,
                'new_this_month': new_channels_month or 0
            }

        except Exception as e:
            logger.error(f"Failed to calculate channel statistics: {str(e)}")
            return {
                'total': 0,
                'public': 0,
                'private': 0,
                'new_this_week': 0,
                'new_this_month': 0
            }

    def _calculate_message_statistics(self) -> Dict[str, Any]:
        """Calculate message-related statistics"""
        try:
            with self.database_handler.database_session() as session:
                from sqlalchemy import select, func

                # Check if Messages table is empty first
                messages_exist = session.query(Messages).count() > 0

                if not messages_exist:
                    logger.debug("No messages in database, returning zero statistics")
                    return {
                        'total': 0,
                        'past_24h': 0,
                        'past_week': 0,
                        'past_month': 0,
                        'past_quarter': 0,
                        'past_year': 0
                    }

                # Total messages
                total_result = session.execute(
                    select(func.count()).select_from(Messages)
                )
                total_messages = total_result.scalar()

                now = datetime.now()

                # Messages in past 24 hours
                day_ago = now - timedelta(days=1)
                messages_24h_result = session.execute(
                    select(func.count()).select_from(Messages).where(
                        Messages.sent_at >= day_ago
                    )
                )
                messages_24h = messages_24h_result.scalar()

                # Messages in past week
                week_ago = now - timedelta(days=7)
                messages_week_result = session.execute(
                    select(func.count()).select_from(Messages).where(
                        Messages.sent_at >= week_ago
                    )
                )
                messages_week = messages_week_result.scalar()

                # Messages in past month
                month_ago = now - timedelta(days=30)
                messages_month_result = session.execute(
                    select(func.count()).select_from(Messages).where(
                        Messages.sent_at >= month_ago
                    )
                )
                messages_month = messages_month_result.scalar()

                # Messages in past 3 months
                quarter_ago = now - timedelta(days=90)
                messages_quarter_result = session.execute(
                    select(func.count()).select_from(Messages).where(
                        Messages.sent_at >= quarter_ago
                    )
                )
                messages_quarter = messages_quarter_result.scalar()

                # Messages in past year
                year_ago = now - timedelta(days=365)
                messages_year_result = session.execute(
                    select(func.count()).select_from(Messages).where(
                        Messages.sent_at >= year_ago
                    )
                )
                messages_year = messages_year_result.scalar()

            return {
                'total': total_messages if total_messages is not None else 0,
                'past_24h': messages_24h if messages_24h is not None else 0,
                'past_week': messages_week if messages_week is not None else 0,
                'past_month': messages_month if messages_month is not None else 0,
                'past_quarter': messages_quarter if messages_quarter is not None else 0,
                'past_year': messages_year if messages_year is not None else 0
            }

        except Exception as e:
            logger.error(f"Failed to calculate message statistics: {str(e)}")
            return {
                'total': 0,
                'past_24h': 0,
                'past_week': 0,
                'past_month': 0,
                'past_quarter': 0,
                'past_year': 0
            }

    async def check_github_releases(self):
        """Check for new PufferBlow releases on GitHub"""
        logger.info("Starting GitHub releases check task")

        try:
            # GitHub API endpoint for latest release
            url = "https://api.github.com/repos/PufferBlow/pufferblow/releases/latest"

            # Make request with timeout
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    release_data = response.json()

                    # Extract relevant information
                    latest_version = release_data.get('tag_name', 'unknown')
                    release_url = release_data.get('html_url', '')
                    published_at = release_data.get('published_at', '')
                    body = release_data.get('body', '')

                    # Store in database or log for now
                    # In a production system, you might want to store this in a database table
                    release_info = {
                        'version': latest_version,
                        'url': release_url,
                        'published_at': published_at,
                        'body': body[:500] if body else ''  # Truncate body
                    }

                    # For now, just log the information
                    logger.info(f"Latest PufferBlow release: {latest_version}")
                    logger.info(f"Release URL: {release_url}")
                    logger.debug(f"Release info: {json.dumps(release_info, indent=2)}")

                    # Store in instance variable for API access
                    self.latest_release = release_info

                else:
                    logger.warning(f"Failed to fetch GitHub release data. Status: {response.status_code}")
                    if response.status_code == 404:
                        logger.info("No releases found or repository not accessible")

            logger.info("GitHub releases check completed")

        except Exception as e:
            logger.error(f"GitHub releases check failed: {str(e)}")
            raise

    def get_latest_release(self) -> Optional[Dict[str, Any]]:
        """Get information about the latest PufferBlow release"""
        return getattr(self, 'latest_release', None)

    def get_server_stats(self) -> Optional[Dict[str, Any]]:
        """Get the latest server statistics"""
        return getattr(self, 'server_stats', None)

    def _initialize_chart_data(self):
        """Initialize chart data structures for historical analytics"""
        # User registration trends
        self.chart_data['user_registrations'] = {
            'daily': [],     # Last 30 days
            'weekly': [],    # Last 12 weeks
            'monthly': []    # Last 12 months
        }

        # Message activity trends
        self.chart_data['message_activity'] = {
            'daily': [],     # Last 30 days
            'weekly': [],    # Last 12 weeks
            'monthly': []    # Last 12 months
        }

        # Online users trends (hourly snapshots)
        self.chart_data['online_users'] = {
            '24h': [],       # Last 24 hours (hourly)
            '7d': []         # Last 7 days (daily averages)
        }

        # Channel creation trends
        self.chart_data['channel_creation'] = {
            'daily': [],     # Last 30 days
            'weekly': [],    # Last 12 weeks
            'monthly': []    # Last 12 months
        }

        # User status distribution (pie chart data)
        self.chart_data['user_status'] = {
            'online': 0,
            'offline': 0,
            'away': 0
        }

        logger.info("Initialized chart data structures")

    def update_chart_data(self):
        """Update historical chart data"""
        logger.info("Starting chart data update")

        try:
            # Update user registration trends
            self._update_user_registration_chart()

            # Update message activity trends
            self._update_message_activity_chart()

            # Update online users trends
            self._update_online_users_chart()

            # Update channel creation trends
            self._update_channel_creation_chart()

            # Update user status distribution
            self._update_user_status_chart()

            logger.info("Chart data update completed")

        except Exception as e:
            logger.error(f"Chart data update failed: {str(e)}")
            raise

    def _update_user_registration_chart(self):
        """Update user registration chart data"""
        try:
            # Daily registrations (last 30 days)
            for i in range(30):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
                end_date = start_date + timedelta(days=1)

                count = self.database_handler.get_user_registration_count_by_period(start_date, end_date)

                chart_entry = ChartData.save_today_metric(
                    chart_type="user_registrations",
                    metric_name="count",
                    value=count,
                    additional_metrics={"date": start_date.strftime('%Y-%m-%d')}
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Weekly registrations (last 12 weeks)
            for i in range(12):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*7)
                # Get to the beginning of the week (Monday)
                start_date = start_date - timedelta(days=start_date.weekday())
                end_date = start_date + timedelta(days=7)

                count = self.database_handler.get_user_registration_count_by_period(start_date, end_date)

                week_key = f"{start_date.strftime('%Y-W%W')}"

                chart_entry = ChartData(
                    chart_type="user_registrations",
                    period_type="weekly",
                    time_key=week_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Monthly registrations (last 12 months)
            for i in range(12):
                start_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*30)
                if i == 0:
                    end_date = datetime.now()
                else:
                    end_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=(i-1)*30)

                count = self.database_handler.get_user_registration_count_by_period(start_date, end_date)

                month_key = start_date.strftime('%Y-%m')

                chart_entry = ChartData(
                    chart_type="user_registrations",
                    period_type="monthly",
                    time_key=month_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

        except Exception as e:
            logger.error(f"Failed to update user registration chart: {str(e)}")
            raise

    def _update_message_activity_chart(self):
        """Update message activity chart data"""
        try:
            # Daily messages (last 30 days)
            for i in range(30):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
                end_date = start_date + timedelta(days=1)

                count = self.database_handler.get_message_count_by_period(start_date, end_date)

                chart_entry = ChartData.save_today_metric(
                    chart_type="message_activity",
                    metric_name="count",
                    value=count,
                    additional_metrics={"date": start_date.strftime('%Y-%m-%d')}
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Weekly messages (last 12 weeks)
            for i in range(12):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*7)
                # Get to the beginning of the week (Monday)
                start_date = start_date - timedelta(days=start_date.weekday())
                end_date = start_date + timedelta(days=7)

                count = self.database_handler.get_message_count_by_period(start_date, end_date)

                week_key = f"{start_date.strftime('%Y-W%W')}"

                chart_entry = ChartData(
                    chart_type="message_activity",
                    period_type="weekly",
                    time_key=week_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Monthly messages (last 12 months)
            for i in range(12):
                start_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*30)
                if i == 0:
                    end_date = datetime.now()
                else:
                    end_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=(i-1)*30)

                count = self.database_handler.get_message_count_by_period(start_date, end_date)

                month_key = start_date.strftime('%Y-%m')

                chart_entry = ChartData(
                    chart_type="message_activity",
                    period_type="monthly",
                    time_key=month_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

        except Exception as e:
            logger.error(f"Failed to update message activity chart: {str(e)}")
            raise

    def _update_online_users_chart(self):
        """Update online users chart data"""
        try:
            # For online users chart, we use mocked data since we don't store hourly online user counts
            # 24h data - hourly snapshots (last 24 hours)
            for i in range(24):
                timestamp = datetime.now() - timedelta(hours=i)
                # For now, we'll calculate based on current online users
                # In a real implementation, you'd store hourly snapshots
                base_count = self.server_stats.get('users', {}).get('online', 0) if hasattr(self, 'server_stats') and self.server_stats else 10

                # Add some variation based on hour (assume peak hours)
                hour = timestamp.hour
                variation = 1.0
                if 9 <= hour <= 17:  # Peak business hours
                    variation = 1.3
                elif 20 <= hour <= 23 or 0 <= hour <= 6:  # Late night/early morning
                    variation = 0.7
                elif 18 <= hour <= 21:  # Evening hours
                    variation = 1.1

                count = int(base_count * variation)
                # Add some randomness
                import random
                count = max(0, count + random.randint(-3, 3))

                chart_entry = ChartData.save_hourly_metric(
                    chart_type="online_users",
                    metric_name="count",
                    value=count,
                    timestamp=timestamp,
                    additional_metrics={"hour": timestamp.strftime('%H')}
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # 7d data - daily averages (last 7 days)
            for i in range(7):
                date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
                # Calculate daily average based on current trends
                base_count = self.server_stats.get('users', {}).get('online', 0) if hasattr(self, 'server_stats') and self.server_stats else 1
                avg_count = int(base_count * (0.8 + 0.4 * (i / 7.0)))  # Trending data

                day_key = date.strftime('%Y-%m-%d')

                chart_entry = ChartData(
                    chart_type="online_users",
                    period_type="7d",
                    time_key=day_key,
                    time_start=date,
                    time_end=date + timedelta(days=1),
                    metrics={"avg_count": avg_count},
                    primary_value=avg_count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

        except Exception as e:
            logger.error(f"Failed to update online users chart: {str(e)}")
            raise

    def _update_channel_creation_chart(self):
        """Update channel creation chart data"""
        try:
            # Daily channel creations (last 30 days)
            for i in range(30):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
                end_date = start_date + timedelta(days=1)

                count = self.database_handler.get_channel_creation_count_by_period(start_date, end_date)

                chart_entry = ChartData.save_today_metric(
                    chart_type="channel_creation",
                    metric_name="count",
                    value=count,
                    additional_metrics={"date": start_date.strftime('%Y-%m-%d')}
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Weekly channel creations (last 12 weeks)
            for i in range(12):
                start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*7)
                start_date = start_date - timedelta(days=start_date.weekday())
                end_date = start_date + timedelta(days=7)

                count = self.database_handler.get_channel_creation_count_by_period(start_date, end_date)

                week_key = f"{start_date.strftime('%Y-W%W')}"

                chart_entry = ChartData(
                    chart_type="channel_creation",
                    period_type="weekly",
                    time_key=week_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

            # Monthly channel creations (last 12 months)
            for i in range(12):
                start_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i*30)
                if i == 0:
                    end_date = datetime.now()
                else:
                    end_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=(i-1)*30)

                count = self.database_handler.get_channel_creation_count_by_period(start_date, end_date)

                month_key = start_date.strftime('%Y-%m')

                chart_entry = ChartData(
                    chart_type="channel_creation",
                    period_type="monthly",
                    time_key=month_key,
                    time_start=start_date,
                    time_end=end_date,
                    metrics={"count": count},
                    primary_value=count
                )
                self.database_handler.save_chart_data_entry(chart_entry)

        except Exception as e:
            logger.error(f"Failed to update channel creation chart: {str(e)}")
            raise

    def _update_user_status_chart(self):
        """Update user status distribution for pie chart"""
        try:
            # Use database handler method to get user status counts
            status_counts = self.database_handler.get_user_status_counts()

            self.chart_data['user_status'] = status_counts

        except Exception as e:
            logger.error(f"Failed to update user status chart: {str(e)}")

    def get_chart_data(self, chart_type: str, period: str = None) -> Dict[str, Any]:
        """
        Get chart data for a specific chart and period

        Args:
            chart_type: Type of chart (user_registrations, message_activity, etc.)
            period: Time period (daily, weekly, monthly, etc.)

        Returns:
            Chart data dictionary with chart_data and raw_stats
        """
        try:
            with self.database_handler.database_session() as session:
                # Query existing chart data from database
                query = session.query(ChartData).filter(ChartData.chart_type == chart_type)

                if period:
                    query = query.filter(ChartData.period_type == period)

                chart_entries = query.order_by(ChartData.time_start).all()

                # Convert to frontend-friendly format
                data_list = []
                for entry in chart_entries:
                    data_list.append(entry.to_chart_format())

                # Calculate raw statistics based on chart type
                raw_stats = self._calculate_raw_stats_for_chart(chart_type, period, chart_entries)

                if period:
                    return {
                        'chart_type': chart_type,
                        'period': period,
                        'chart_data': data_list,
                        'raw_stats': raw_stats,
                        'last_updated': datetime.now().isoformat()
                    }
                else:
                    # Group by period type
                    grouped_data = {}
                    for entry in chart_entries:
                        period_type = entry.period_type
                        if period_type not in grouped_data:
                            grouped_data[period_type] = []
                        grouped_data[period_type].append(entry.to_chart_format())

                    return {
                        'chart_type': chart_type,
                        'chart_data': grouped_data,
                        'raw_stats': raw_stats,
                        'last_updated': datetime.now().isoformat()
                    }

        except Exception as e:
            logger.error(f"Failed to get chart data for {chart_type}: {str(e)}")
            return {
                'chart_type': chart_type,
                'error': f"Failed to retrieve data: {str(e)}",
                'chart_data': {},
                'raw_stats': {},
                'last_updated': datetime.now().isoformat()
            }

    def _calculate_raw_stats_for_chart(self, chart_type: str, period: str = None, chart_entries: List = None) -> Dict[str, Any]:
        """
        Calculate raw statistics for a given chart type

        Args:
            chart_type: Type of chart (user_registrations, message_activity, etc.)
            period: Time period (daily, weekly, monthly, etc.)
            chart_entries: List of chart data entries

        Returns:
            Raw statistics dictionary
        """
        try:
            # Get current server stats
            server_stats = getattr(self, 'server_stats', {})

            # Extract stats that might be used in multiple chart types
            users_stats = server_stats.get('users', {})

            if chart_type == 'user_registrations':
                users_stats = server_stats.get('users', {})

                # Calculate growth metrics from chart entries
                growth_stats = self._calculate_growth_stats(chart_entries)

                return {
                    'total_users': users_stats.get('total', 0),
                    'new_this_week': users_stats.get('new_this_week', 0),
                    'new_this_month': users_stats.get('new_this_month', 0),
                    'online_now': users_stats.get('online', 0),
                    'recently_active': users_stats.get('recently_active', 0),
                    'growth_rate_week': growth_stats.get('weekly_growth', 0),
                    'growth_rate_month': growth_stats.get('monthly_growth', 0),
                    'peak_registrations': growth_stats.get('peak', 0),
                    'avg_daily_registrations': growth_stats.get('avg_daily', 0)
                }

            elif chart_type == 'message_activity':
                messages_stats = server_stats.get('messages', {})

                # Calculate message growth metrics
                growth_stats = self._calculate_growth_stats(chart_entries)

                return {
                    'total_messages': messages_stats.get('total', 0),
                    'messages_today': messages_stats.get('past_24h', 0),
                    'messages_this_week': messages_stats.get('past_week', 0),
                    'messages_this_month': messages_stats.get('past_month', 0),
                    'messages_this_quarter': messages_stats.get('past_quarter', 0),
                    'messages_this_year': messages_stats.get('past_year', 0),
                    'growth_rate_week': growth_stats.get('weekly_growth', 0),
                    'growth_rate_month': growth_stats.get('monthly_growth', 0),
                    'peak_activity': growth_stats.get('peak', 0),
                    'avg_daily_messages': growth_stats.get('avg_daily', 0),
                    'messages_per_user': messages_stats.get('total', 0) / max(users_stats.get('total', 1), 1)
                }

            elif chart_type == 'online_users':
                users_stats = server_stats.get('users', {})

                # Calculate online user metrics
                online_metrics = self._calculate_online_user_stats(chart_entries)

                return {
                    'currently_online': users_stats.get('online', 0),
                    'recently_active': users_stats.get('recently_active', 0),
                    'peak_online_today': online_metrics.get('peak_today', 0),
                    'avg_online_today': online_metrics.get('avg_today', 0),
                    'peak_online_week': online_metrics.get('peak_week', 0),
                    'avg_online_week': online_metrics.get('avg_week', 0),
                    'total_users': users_stats.get('total', 0),
                    'online_percentage': (users_stats.get('online', 0) / max(users_stats.get('total', 1), 1)) * 100
                }

            elif chart_type == 'channel_creation':
                channels_stats = server_stats.get('channels', {})

                # Calculate channel growth metrics
                growth_stats = self._calculate_growth_stats(chart_entries)

                return {
                    'total_channels': channels_stats.get('total', 0),
                    'public_channels': channels_stats.get('public', 0),
                    'private_channels': channels_stats.get('private', 0),
                    'new_this_week': channels_stats.get('new_this_week', 0),
                    'new_this_month': channels_stats.get('new_this_month', 0),
                    'growth_rate_week': growth_stats.get('weekly_growth', 0),
                    'growth_rate_month': growth_stats.get('monthly_growth', 0),
                    'peak_creations': growth_stats.get('peak', 0),
                    'avg_daily_creations': growth_stats.get('avg_daily', 0)
                }

            elif chart_type == 'user_status':
                # For pie chart, status counts are already in the chart_entries
                status_counts = {}
                if chart_entries and len(chart_entries) > 0:
                    # Assume the pie chart data contains the counts
                    status_counts = chart_entries[0] if isinstance(chart_entries[0], dict) else {}

                return {
                    'online_users': status_counts.get('online', 0),
                    'offline_users': status_counts.get('offline', 0),
                    'away_users': status_counts.get('away', 0),
                    'total_users': sum(status_counts.values()) if status_counts else 0
                }

            return {}

        except Exception as e:
            logger.error(f"Failed to calculate raw stats for {chart_type}: {str(e)}")
            return {}

    def _calculate_growth_stats(self, chart_entries: List) -> Dict[str, Any]:
        """Calculate growth statistics from chart entries"""
        try:
            if not chart_entries:
                return {'weekly_growth': 0, 'monthly_growth': 0, 'peak': 0, 'avg_daily': 0}

            # Extract primary values
            values = []
            for entry in chart_entries:
                if hasattr(entry, 'primary_value'):
                    values.append(entry.primary_value or 0)
                elif isinstance(entry, dict) and 'y' in entry:
                    values.append(entry['y'])
                elif isinstance(entry, dict) and 'data' in entry:
                    values.append(entry['data'])

            if not values:
                return {'weekly_growth': 0, 'monthly_growth': 0, 'peak': 0, 'avg_daily': 0}

            # Calculate metrics
            peak = max(values) if values else 0
            avg_daily = sum(values) / len(values) if values else 0

            # Calculate growth rates (simplified - comparing first half vs second half)
            mid_point = len(values) // 2
            if mid_point > 0:
                first_half_avg = sum(values[:mid_point]) / mid_point
                second_half_avg = sum(values[mid_point:]) / (len(values) - mid_point)

                weekly_growth = ((second_half_avg - first_half_avg) / max(first_half_avg, 1)) * 100 if first_half_avg else 0
                monthly_growth = weekly_growth * 4  # Rough estimate
            else:
                weekly_growth = 0
                monthly_growth = 0

            return {
                'weekly_growth': round(weekly_growth, 2),
                'monthly_growth': round(monthly_growth, 2),
                'peak': peak,
                'avg_daily': round(avg_daily, 2)
            }

        except Exception as e:
            logger.error(f"Failed to calculate growth stats: {str(e)}")
            return {'weekly_growth': 0, 'monthly_growth': 0, 'peak': 0, 'avg_daily': 0}

    def get_raw_stats(self, chart_type: str, period: str = None) -> Dict[str, Any]:
        """
        Get raw statistics for a chart type and period

        Args:
            chart_type: Type of chart (user_registrations, message_activity, etc.)
            period: Time period (daily, weekly, monthly, etc.)

        Returns:
            Raw statistics dictionary
        """
        try:
            # Get chart entries from database
            with self.database_handler.database_session() as session:
                from pufferblow.api.database.tables.chart_data import ChartData
                query = session.query(ChartData).filter(ChartData.chart_type == chart_type)

                if period:
                    query = query.filter(ChartData.period_type == period)

                chart_entries = query.order_by(ChartData.time_start).all()

            # Calculate raw stats using the existing method
            return self._calculate_raw_stats_for_chart(chart_type, period, chart_entries)

        except Exception as e:
            logger.error(f"Failed to get raw stats for {chart_type}: {str(e)}")
            return {}

    def _calculate_online_user_stats(self, chart_entries: List) -> Dict[str, Any]:
        """Calculate online user statistics"""
        try:
            if not chart_entries:
                return {'peak_today': 0, 'avg_today': 0, 'peak_week': 0, 'avg_week': 0}

            # Separate hourly (24h) and daily (7d) data
            hourly_data = []
            daily_data = []

            for entry in chart_entries:
                if hasattr(entry, 'period_type'):
                    if entry.period_type == '24h':
                        hourly_data.append(entry.primary_value or 0)
                    elif entry.period_type == '7d':
                        daily_data.append(entry.primary_value or 0)

            peak_today = max(hourly_data) if hourly_data else 0
            avg_today = sum(hourly_data) / len(hourly_data) if hourly_data else 0
            peak_week = max(daily_data) if daily_data else 0
            avg_week = sum(daily_data) / len(daily_data) if daily_data else 0

            return {
                'peak_today': peak_today,
                'avg_today': round(avg_today, 2),
                'peak_week': peak_week,
                'avg_week': round(avg_week, 2)
            }

        except Exception as e:
            logger.error(f"Failed to calculate online user stats: {str(e)}")
            return {'peak_today': 0, 'avg_today': 0, 'peak_week': 0, 'avg_week': 0}

@asynccontextmanager
async def lifespan_background_tasks():
    """Lifespan function to start background tasks"""
    from pufferblow.api_initializer import api_initializer

    # Start the scheduler in background
    if api_initializer.is_loaded and hasattr(api_initializer, 'background_tasks_manager'):
        scheduler_task = asyncio.create_task(
            api_initializer.background_tasks_manager.start_scheduler()
        )

        # Store the task so we can cancel it on shutdown
        api_initializer._scheduler_task = scheduler_task

        yield

        # Cancel scheduler on shutdown
        if hasattr(api_initializer, '_scheduler_task'):
            api_initializer._scheduler_task.cancel()
            try:
                await api_initializer._scheduler_task
            except asyncio.CancelledError:
                pass
    else:
        yield
