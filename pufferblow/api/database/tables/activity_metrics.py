from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Float
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt

class ActivityMetrics(Base):
    """Activity metrics table to track server liveness and popularity"""
    __tablename__ = "activity_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Time period (daily, weekly, monthly)
    period: Mapped[str] = mapped_column(String, nullable=False)  # 'daily', 'weekly', 'monthly'
    date: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Start date of the period

    # User activity
    total_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    new_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # Users who joined in this period
    active_users: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # Users who sent messages
    online_users_avg: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    online_users_peak: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Message activity
    total_messages: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    messages_this_period: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    messages_per_hour: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    channels_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # Number of channels with messages

    # Engagement metrics
    user_engagement_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # % of users who are active
    messages_per_active_user: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    channel_utilization_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # % of channels used

    # File and media activity
    files_uploaded: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_file_size_mb: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Server stats at time of recording
    server_uptime_hours: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=date_in_gmt, nullable=False)

    def __repr__(self) -> str:
        return (
            f"ActivityMetrics(period={self.period!r}, date={self.date!r}, "
            f"total_users={self.total_users}, active_users={self.active_users}, "
            f"total_messages={self.total_messages}, messages_this_period={self.messages_this_period})"
        )
