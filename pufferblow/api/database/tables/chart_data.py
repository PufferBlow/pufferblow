from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional
import json

from sqlalchemy import String, Integer, DateTime, JSON, Float
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class ChartData(Base):
    """Chart data metrics for server analytics"""
    __tablename__ = "chart_data"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chart_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # user_registrations, message_activity, etc.
    period_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # daily, weekly, monthly, hourly, 7d
    time_key: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # date/week/month/timestamp string
    time_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Actual start datetime
    time_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Actual end datetime

    # Metrics data stored as JSON
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Additional computed values for quick queries
    primary_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # Main value (count, avg_count, etc.)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: date_in_gmt(format="%Y-%m-%d %H:%M:%S"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: date_in_gmt(format="%Y-%m-%d %H:%M:%S"), onupdate=lambda: date_in_gmt(format="%Y-%m-%d %H:%M:%S"))

    def __repr__(self) -> str:
        return (
            f"ChartData(id={self.id!r}, "
            f"chart_type={self.chart_type!r}, "
            f"period_type={self.period_type!r}, "
            f"time_key={self.time_key!r}, "
            f"primary_value={self.primary_value!r})"
        )

    @classmethod
    def save_today_metric(
        cls,
        chart_type: str,
        metric_name: str,
        value: float|int,
        additional_metrics: Optional[dict] = None
    ) -> 'ChartData':
        """
        Save a simple metric for today (daily period).

        Args:
            chart_type (str): Chart type like 'user_registrations'
            metric_name (str): Metric name like 'count'
            value (float|int): The primary metric value
            additional_metrics (dict, optional): Additional metrics

        Returns:
            ChartData: The created chart data entry
        """
        from datetime import datetime

        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        tomorrow = today.replace(day=today.day + 1)

        metrics = {metric_name: value}
        if additional_metrics:
            metrics.update(additional_metrics)

        return cls(
            chart_type=chart_type,
            period_type="daily",
            time_key=today.strftime('%Y-%m-%d'),
            time_start=today,
            time_end=tomorrow,
            metrics=metrics,
            primary_value=float(value)
        )

    @classmethod
    def save_hourly_metric(
        cls,
        chart_type: str,
        metric_name: str,
        value: float|int,
        timestamp: Optional[datetime] = None,
        additional_metrics: Optional[dict] = None
    ) -> 'ChartData':
        """
        Save an hourly metric.

        Args:
            chart_type (str): Chart type like 'online_users'
            metric_name (str): Metric name like '_count'
            value (float|int): The metric value
            timestamp (datetime, optional): Specific timestamp, defaults to current hour
            additional_metrics (dict, optional): Additional metrics

        Returns:
            ChartData: The created chart data entry
        """
        if timestamp is None:
            timestamp = datetime.now()

        hour_start = timestamp.replace(minute=0, second=0, microsecond=0)

        # Calculate hour_end, handling day rollover for hour 23
        if hour_start.hour == 23:
            # Special case for hour 23 - goes to next day at 00:00
            hour_end = hour_start.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        else:
            hour_end = hour_start.replace(hour=hour_start.hour + 1)

        metrics = {metric_name: value}
        if additional_metrics:
            metrics.update(additional_metrics)

        return cls(
            chart_type=chart_type,
            period_type="hourly",
            time_key=hour_start.strftime('%Y-%m-%d %H:00'),
            time_start=hour_start,
            time_end=hour_end,
            metrics=metrics,
            primary_value=float(value)
        )

    def to_chart_format(self) -> dict:
        """
        Convert to frontend-friendly chart format.

        Returns:
            dict: Chart-ready data structure
        """
        result = {
            'time_key': self.time_key,
            'primary_value': self.primary_value,
            'metrics': self.metrics,
            'period': self.period_type,
            'timestamp': self.time_start.isoformat()
        }

        # Add specific fields based on period type
        if self.period_type == 'daily':
            result['date'] = self.time_key
        elif self.period_type in ['weekly', 'monthly']:
            result[self.period_type] = self.time_key
        elif self.period_type == 'hourly':
            result['timestamp'] = self.time_key

        return result
