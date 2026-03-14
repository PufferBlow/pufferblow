"""Scheduler mixin for background tasks."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from loguru import logger


class BackgroundTaskSchedulerMixin:
    def register_task(
        self,
        task_id: str,
        task_func: Callable,
        interval_minutes: int | None = None,
        interval_hours: int | None = None,
        enabled: bool = True,
        **kwargs,
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
            "id": task_id,
            "func": task_func,
            "interval_minutes": interval_minutes,
            "interval_hours": interval_hours,
            "enabled": enabled,
            "kwargs": kwargs,
            "next_run": (
                datetime.now()
                + timedelta(minutes=interval_minutes or 0, hours=interval_hours or 0)
                if (interval_minutes or interval_hours)
                else None
            ),
        }

        self.task_stats[task_id] = {
            "runs": 0,
            "errors": 0,
            "last_run": None,
            "last_error": None,
            "total_runtime": 0.0,
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
            if not task_info["enabled"]:
                continue

            if task_info["next_run"] and now >= task_info["next_run"]:
                try:
                    await self.run_task(task_id)

                    # Schedule next run
                    interval = timedelta(
                        minutes=task_info["interval_minutes"] or 0,
                        hours=task_info["interval_hours"] or 0,
                    )
                    task_info["next_run"] = now + interval

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
                self._execute_task_func(task_info["func"], **task_info["kwargs"])
            )

            self.running_tasks[task_id] = task

            # Wait for completion
            await task

            # Update statistics
            self.task_stats[task_id]["runs"] += 1
            self.task_stats[task_id]["last_run"] = start_time
            duration = (datetime.now() - start_time).total_seconds()
            self.task_stats[task_id]["total_runtime"] += duration

            logger.info(f"Completed background task: {task_id}")
            return True

        except Exception as e:
            logger.error(f"Background task {task_id} failed: {str(e)}")
            self.task_stats[task_id]["errors"] += 1
            self.task_stats[task_id]["last_error"] = str(e)
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

    def get_task_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all registered tasks"""
        status = {}

        for task_id, task_info in self.tasks.items():
            status[task_id] = {
                "registered": True,
                "enabled": task_info["enabled"],
                "next_run": (
                    task_info["next_run"].isoformat() if task_info["next_run"] else None
                ),
                "running": task_id in self.running_tasks,
                **self.task_stats[task_id],
            }

        return status

    def enable_task(self, task_id: str) -> bool:
        """Enable a task"""
        if task_id in self.tasks:
            self.tasks[task_id]["enabled"] = True
            logger.info(f"Enabled background task: {task_id}")
            return True
        return False

    def disable_task(self, task_id: str) -> bool:
        """Disable a task"""
        if task_id in self.tasks:
            self.tasks[task_id]["enabled"] = False
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
