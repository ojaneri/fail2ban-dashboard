"""
FastAPI backend for Fail2Ban SOC Dashboard.
Provides API endpoints for attack statistics, banned IPs, and real-time updates.
"""
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
import async_timeout

# Local imports
from models import Base, AttackLog, CountryStats, BannedIP, JailStats
from parser import (
    parse_log_file_async, 
    find_log_path, 
    generate_demo_data,
    sanitize_ip,
    sanitize_jail
)
from geoip import get_country_code_async, validate_ip


# Database configuration
DATABASE_URL = "sqlite+aiosqlite:///fail2ban_dashboard.db"

# Global state
engine = None
async_session_maker = None
websocket_connections: List[WebSocket] = []
background_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    global engine, async_session_maker, background_task
    
    # Startup
    engine = create_async_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    async_session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Start background log parser
    background_task = asyncio.create_task(parse_logs_periodically())
    
    # Check if we have real log data, don't seed demo data
    # await seed_demo_data_if_empty()
    
    yield
    
    # Shutdown
    if background_task:
        background_task.cancel()
        try:
            await background_task
        except asyncio.CancelledError:
            pass
    
    await engine.dispose()


async def seed_demo_data_if_empty():
    """Seed demo data if the database is empty."""
    async with async_session_maker() as session:
        # Check if we have any data
        result = await session.execute(select(func.count(AttackLog.id)))
        count = result.scalar()
        
        if count == 0:
            # Generate demo data
            demo_entries = generate_demo_data()
            
            # Process each entry
            for entry in demo_entries:
                country_code, country_name = await get_country_code_async(entry.ip)
                
                log_entry = AttackLog(
                    ip=entry.ip,
                    country=country_code,
                    country_name=country_name,
                    jail=entry.jail,
                    timestamp=entry.timestamp,
                    action=entry.action,
                    raw_log=entry.raw_log
                )
                session.add(log_entry)
                
                # Update country stats
                if country_code:
                    await update_country_stats(session, country_code, country_name)
                
                # Update jail stats
                await update_jail_stats(session, entry.jail, entry.action)
                
                # Track banned IPs
                if entry.action == "Ban":
                    await update_banned_ips(session, entry.ip, entry.jail, entry.timestamp, country_code, country_name)
            
            await session.commit()
            print(f"Seeded {len(demo_entries)} demo entries")


async def update_country_stats(session: AsyncSession, country_code: str, country_name: str):
    """Update country statistics."""
    result = await session.execute(
        select(CountryStats).where(CountryStats.country == country_code)
    )
    stats = result.scalar_one_or_none()
    
    if stats:
        stats.total_attacks += 1
        stats.last_updated = datetime.utcnow()
    else:
        stats = CountryStats(
            country=country_code,
            country_name=country_name or "Unknown",
            total_attacks=1,
            unique_ips=1,
            last_updated=datetime.utcnow()
        )
        session.add(stats)


async def update_jail_stats(session: AsyncSession, jail: str, action: str):
    """Update jail statistics."""
    jail = sanitize_jail(jail)
    result = await session.execute(
        select(JailStats).where(JailStats.jail == jail)
    )
    stats = result.scalar_one_or_none()
    
    if stats:
        stats.total_bans += 1
        if action == "Ban":
            stats.active_bans += 1
        elif action == "Unban" and stats.active_bans > 0:
            stats.active_bans -= 1
        stats.last_updated = datetime.utcnow()
    else:
        stats = JailStats(
            jail=jail,
            total_bans=1,
            active_bans=1 if action == "Ban" else 0,
            last_updated=datetime.utcnow()
        )
        session.add(stats)


async def update_banned_ips(session: AsyncSession, ip: str, jail: str, timestamp: datetime, 
                            country_code: Optional[str], country_name: Optional[str]):
    """Update banned IPs tracking."""
    result = await session.execute(
        select(BannedIP).where(BannedIP.ip == ip)
    )
    banned = result.scalar_one_or_none()
    
    if banned:
        banned.ban_count += 1
        banned.ban_timestamp = timestamp
        banned.jail = jail
    else:
        banned = BannedIP(
            ip=ip,
            country=country_code,
            country_name=country_name,
            jail=jail,
            ban_timestamp=timestamp,
            ban_count=1
        )
        session.add(banned)


# Create FastAPI app
app = FastAPI(
    title="Fail2Ban SOC Dashboard API",
    description="API for Fail2Ban attack monitoring and analytics",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Background task for log parsing
async def parse_logs_periodically(interval: int = 30):
    """Periodically parse Fail2Ban logs."""
    while True:
        try:
            async with async_timeout.timeout(25):
                log_path = find_log_path()
                
                if log_path:
                    entries = await parse_log_file_async(log_path)
                    
                    if entries:
                        await process_parsed_entries(entries)
                        await broadcast_update({"type": "new_entries", "count": len(entries)})
                else:
                    # No log file found, just wait
                    pass
                    
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Error parsing logs: {e}")
        
        await asyncio.sleep(interval)


async def process_parsed_entries(entries: List):
    """Process parsed log entries and store in database."""
    async with async_session_maker() as session:
        for entry in entries:
            # Validate IP
            if not validate_ip(entry.ip):
                continue
            
            # Get country
            country_code, country_name = await get_country_code_async(entry.ip)
            
            # Create log entry
            log_entry = AttackLog(
                ip=entry.ip,
                country=country_code,
                country_name=country_name,
                jail=sanitize_jail(entry.jail),
                timestamp=entry.timestamp,
                action=entry.action,
                raw_log=entry.raw_log
            )
            session.add(log_entry)
            
            # Update stats
            if country_code:
                await update_country_stats(session, country_code, country_name)
            
            await update_jail_stats(session, entry.jail, entry.action)
            
            # Update banned IPs
            if entry.action == "Ban":
                await update_banned_ips(
                    session, entry.ip, entry.jail, entry.timestamp, 
                    country_code, country_name
                )
        
        await session.commit()


async def broadcast_update(data: Dict[str, Any]):
    """Broadcast update to all WebSocket clients."""
    if websocket_connections:
        message = json.dumps(data)
        disconnected = []
        
        for ws in websocket_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        
        # Remove disconnected clients
        for ws in disconnected:
            websocket_connections.remove(ws)


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates."""
    await websocket.accept()
    websocket_connections.append(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_text(json.dumps({"type": "connected", "message": "WebSocket connected"}))
        
        # Keep connection alive
        while True:
            try:
                # Wait for messages (can be used for commands)
                data = await websocket.receive_text()
                # Handle any client messages if needed
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Fail2Ban SOC Dashboard API", "version": "1.0.0"}


@app.get("/api/stats/overview")
async def get_stats_overview():
    """
    Get dashboard summary statistics.
    Returns total bans, today, this week, and top countries.
    """
    async with async_session_maker() as session:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        
        # Total bans
        result = await session.execute(
            select(func.count(AttackLog.id)).where(AttackLog.action == "Ban")
        )
        total_bans = result.scalar() or 0
        
        # Today's bans
        result = await session.execute(
            select(func.count(AttackLog.id)).where(
                and_(
                    AttackLog.action == "Ban",
                    AttackLog.timestamp >= today_start
                )
            )
        )
        today_bans = result.scalar() or 0
        
        # This week's bans
        result = await session.execute(
            select(func.count(AttackLog.id)).where(
                and_(
                    AttackLog.action == "Ban",
                    AttackLog.timestamp >= week_start
                )
            )
        )
        week_bans = result.scalar() or 0
        
        # Active bans (currently banned)
        result = await session.execute(select(func.count(BannedIP.id)))
        active_bans = result.scalar() or 0
        
        # Top countries
        result = await session.execute(
            select(CountryStats)
            .order_by(desc(CountryStats.total_attacks))
            .limit(10)
        )
        top_countries = []
        for row in result.scalars():
            top_countries.append({
                "country": row.country,
                "country_name": row.country_name,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips
            })
        
        # Jail statistics
        result = await session.execute(
            select(JailStats).order_by(desc(JailStats.total_bans))
        )
        jails = []
        for row in result.scalars():
            jails.append({
                "jail": row.jail,
                "total_bans": row.total_bans,
                "active_bans": row.active_bans
            })
        
        return {
            "total_bans": total_bans,
            "today_bans": today_bans,
            "week_bans": week_bans,
            "active_bans": active_bans,
            "top_countries": top_countries,
            "jails": jails,
            "timestamp": now.isoformat()
        }


@app.get("/api/stats/attacks-over-time")
async def get_attacks_over_time(
    days: int = Query(7, ge=1, le=90),
    interval: str = Query("hour", regex="^(hour|day)$")
):
    """
    Get time series data for attacks over time.
    
    Args:
        days: Number of days to look back
        interval: Aggregation interval (hour or day)
    """
    async with async_session_maker() as session:
        start_date = datetime.utcnow() - timedelta(days=days)
        
        if interval == "hour":
            # Group by hour
            query = select(
                func.strftime("%Y-%m-%d %H:00", AttackLog.timestamp).label("period"),
                func.count(AttackLog.id).label("count")
            ).where(
                and_(
                    AttackLog.timestamp >= start_date,
                    AttackLog.action == "Ban"
                )
            ).group_by("period").order_by("period")
        else:
            # Group by day
            query = select(
                func.strftime("%Y-%m-%d", AttackLog.timestamp).label("period"),
                func.count(AttackLog.id).label("count")
            ).where(
                and_(
                    AttackLog.timestamp >= start_date,
                    AttackLog.action == "Ban"
                )
            ).group_by("period").order_by("period")
        
        result = await session.execute(query)
        data = [{"period": row.period, "count": row.count} for row in result]
        
        return {
            "interval": interval,
            "days": days,
            "data": data
        }


@app.get("/api/stats/top-attackers")
async def get_top_attackers(
    limit: int = Query(20, ge=1, le=100)
):
    """
    Get top attacking IP addresses.
    
    Args:
        limit: Maximum number of results
    """
    async with async_session_maker() as session:
        query = select(
            AttackLog.ip,
            AttackLog.country,
            AttackLog.country_name,
            func.count(AttackLog.id).label("attack_count")
        ).where(
            AttackLog.action == "Ban"
        ).group_by(
            AttackLog.ip
        ).order_by(
            desc("attack_count")
        ).limit(limit)
        
        result = await session.execute(query)
        attackers = []
        
        for row in result:
            attackers.append({
                "ip": row.ip,
                "country": row.country,
                "country_name": row.country_name,
                "attack_count": row.attack_count
            })
        
        return {
            "limit": limit,
            "attackers": attackers
        }


@app.get("/api/stats/top-countries")
async def get_top_countries(
    limit: int = Query(10, ge=1, le=50)
):
    """
    Get country breakdown of attacks.
    
    Args:
        limit: Maximum number of results
    """
    async with async_session_maker() as session:
        query = select(CountryStats).order_by(
            desc(CountryStats.total_attacks)
        ).limit(limit)
        
        result = await session.execute(query)
        countries = []
        
        for row in result.scalars():
            countries.append({
                "country": row.country,
                "country_name": row.country_name,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips
            })
        
        return {
            "limit": limit,
            "countries": countries
        }


@app.get("/api/stats/heatmap-data")
async def get_heatmap_data():
    """
    Get attack intensity data by country for map visualization.
    """
    async with async_session_maker() as session:
        query = select(CountryStats).order_by(
            desc(CountryStats.total_attacks)
        )
        
        result = await session.execute(query)
        heatmap = []
        
        for row in result.scalars():
            heatmap.append({
                "country": row.country,
                "country_name": row.country_name,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips,
                "intensity": min(100, row.total_attacks / 10)  # Normalize to 0-100
            })
        
        return {
            "heatmap": heatmap
        }


@app.get("/api/banned-ips")
async def get_banned_ips(
    jail: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """
    Get list of currently banned IPs.
    
    Args:
        jail: Filter by jail name
        country: Filter by country code
        limit: Maximum number of results
        offset: Offset for pagination
    """
    async with async_session_maker() as session:
        query = select(BannedIP).order_by(desc(BannedIP.ban_timestamp))
        
        # Apply filters
        if jail:
            query = query.where(BannedIP.jail == sanitize_jail(jail))
        if country:
            query = query.where(BannedIP.country == country.upper())
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_query)).scalar()
        
        # Apply pagination
        query = query.limit(limit).offset(offset)
        
        result = await session.execute(query)
        ips = []
        
        for row in result.scalars():
            ips.append({
                "ip": row.ip,
                "country": row.country,
                "country_name": row.country_name,
                "jail": row.jail,
                "ban_timestamp": row.ban_timestamp.isoformat(),
                "ban_count": row.ban_count
            })
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "ips": ips
        }


@app.get("/api/logs")
async def get_logs(
    ip: Optional[str] = Query(None),
    jail: Optional[str] = Query(None),
    action: Optional[str] = Query(None, regex="^(Ban|Unban)$"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Queryable logs with filters.
    
    Args:
        ip: Filter by IP address
        jail: Filter by jail name
        action: Filter by action type (Ban/Unban)
        start_date: Filter by start date
        end_date: Filter by end date
        limit: Maximum number of results
        offset: Offset for pagination
    """
    async with async_session_maker() as session:
        query = select(AttackLog).order_by(desc(AttackLog.timestamp))
        
        # Apply filters
        if ip:
            if validate_ip(ip):
                query = query.where(AttackLog.ip == ip)
        if jail:
            query = query.where(AttackLog.jail == sanitize_jail(jail))
        if action:
            query = query.where(AttackLog.action == action)
        if start_date:
            query = query.where(AttackLog.timestamp >= start_date)
        if end_date:
            query = query.where(AttackLog.timestamp <= end_date)
        
        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_query)).scalar()
        
        # Apply pagination
        query = query.limit(limit).offset(offset)
        
        result = await session.execute(query)
        logs = []
        
        for row in result.scalars():
            logs.append({
                "id": row.id,
                "ip": row.ip,
                "country": row.country,
                "country_name": row.country_name,
                "jail": row.jail,
                "timestamp": row.timestamp.isoformat(),
                "action": row.action,
                "raw_log": row.raw_log
            })
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "logs": logs
        }


@app.post("/api/refresh")
async def refresh_data():
    """
    Force refresh of data from logs.
    """
    log_path = find_log_path()
    
    if not log_path:
        return {"status": "no_log_file", "message": "No Fail2Ban log file found"}
    
    entries = await parse_log_file_async(log_path)
    await process_parsed_entries(entries)
    
    return {
        "status": "success", 
        "message": f"Processed {len(entries)} log entries"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_websockets": len(websocket_connections)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
