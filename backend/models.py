"""
Database models for Fail2Ban SOC Dashboard.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Index, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class AttackLog(Base):
    """
    Model for storing Fail2Ban attack logs.
    """
    __tablename__ = "attack_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    country: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    country_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    jail: Mapped[str] = mapped_column(String(100), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_log: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    __table_args__ = (
        Index("idx_ip_timestamp", "ip", "timestamp"),
        Index("idx_jail_timestamp", "jail", "timestamp"),
        Index("idx_country_timestamp", "country", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AttackLog(id={self.id}, ip={self.ip}, jail={self.jail}, timestamp={self.timestamp})>"


class CountryStats(Base):
    """
    Model for storing aggregated country statistics.
    """
    __tablename__ = "country_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    country: Mapped[str] = mapped_column(String(2), unique=True, nullable=False)
    country_name: Mapped[str] = mapped_column(String(100), nullable=False)
    total_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unique_ips: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<CountryStats(country={self.country}, total_attacks={self.total_attacks})>"


class BannedIP(Base):
    """
    Model for storing currently banned IPs.
    """
    __tablename__ = "banned_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    country: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    country_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    jail: Mapped[str] = mapped_column(String(100), nullable=False)
    ban_timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    ban_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    def __repr__(self) -> str:
        return f"<BannedIP(ip={self.ip}, jail={self.jail})>"


class JailStats(Base):
    """
    Model for storing jail-specific statistics.
    """
    __tablename__ = "jail_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jail: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    total_bans: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_bans: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<JailStats(jail={self.jail}, total_bans={self.total_bans})>"
