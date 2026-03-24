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

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
import async_timeout

# Local imports
from models import Base, AttackLog, CountryStats, BannedIP, JailStats
from parser import (
    parse_log_file_async,
    parse_all_logs_async,
    find_log_path,
    generate_demo_data,
    sanitize_ip,
    sanitize_jail
)
from geoip import get_country_code_async, get_country_codes_batch, validate_ip


# Database configuration
DATABASE_URL = "sqlite+aiosqlite:///fail2ban_dashboard.db"

# Global state
engine = None
async_session_maker = None
websocket_connections: List[WebSocket] = []
background_task: Optional[asyncio.Task] = None
_last_processed_timestamp: Optional[datetime] = None


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
    
    # Start background log parser (also handles initial historical import)
    background_task = asyncio.create_task(parse_logs_periodically())

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
        stats.last_updated = datetime.now()
    else:
        stats = CountryStats(
            country=country_code,
            country_name=country_name or "Unknown",
            total_attacks=1,
            unique_ips=1,
            last_updated=datetime.now()
        )
        session.add(stats)
        await session.flush()


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
        stats.last_updated = datetime.now()
    else:
        stats = JailStats(
            jail=jail,
            total_bans=1,
            active_bans=1 if action == "Ban" else 0,
            last_updated=datetime.now()
        )
        session.add(stats)
        await session.flush()


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
        await session.flush()


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
    """Periodically parse Fail2Ban logs. On first run, imports all historical logs."""
    global _last_processed_timestamp
    first_run = True

    while True:
        try:
            if first_run:
                # Import all logs (including rotated/gzipped) on first run
                print("Importando logs históricos do fail2ban (background)...")
                entries = await parse_all_logs_async()
                first_run = False
            else:
                async with async_timeout.timeout(25):
                    log_path = find_log_path()
                    entries = await parse_log_file_async(log_path) if log_path else []

            if entries:
                if _last_processed_timestamp is not None:
                    new_entries = [e for e in entries if e.timestamp > _last_processed_timestamp]
                else:
                    new_entries = entries

                if new_entries:
                    # Process in chunks to avoid giant SQLite sessions
                    CHUNK = 500
                    total = 0
                    for i in range(0, len(new_entries), CHUNK):
                        chunk = new_entries[i:i + CHUNK]
                        await process_parsed_entries(chunk)
                        total += len(chunk)

                    _last_processed_timestamp = max(e.timestamp for e in new_entries)
                    print(f"Processadas {total} entradas do fail2ban.")
                    await broadcast_update({"type": "new_entries", "count": total})
                elif _last_processed_timestamp is None and entries:
                    _last_processed_timestamp = max(e.timestamp for e in entries)

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Error parsing logs: {e}")

        await asyncio.sleep(interval)


async def process_parsed_entries(entries: List):
    """Process parsed log entries and store in database."""
    if not entries:
        return

    async with async_session_maker() as session:
        # Load existing entries in the time range of this batch to skip duplicates
        # (avoids SQLite IN-clause limit with thousands of timestamps)
        min_ts = min(e.timestamp for e in entries)
        max_ts = max(e.timestamp for e in entries)
        existing_result = await session.execute(
            select(AttackLog.ip, AttackLog.jail, AttackLog.timestamp, AttackLog.action)
            .where(AttackLog.timestamp >= min_ts, AttackLog.timestamp <= max_ts)
        )
        existing_set = {(r.ip, r.jail, r.timestamp, r.action) for r in existing_result}

        # Pre-load country data from DB for this time range
        known_geoip: Dict[str, tuple] = {}
        geoip_rows = await session.execute(
            select(AttackLog.ip, AttackLog.country, AttackLog.country_name)
            .where(AttackLog.timestamp >= min_ts, AttackLog.timestamp <= max_ts,
                   AttackLog.country.isnot(None))
            .distinct()
        )
        for row in geoip_rows:
            known_geoip[row.ip] = (row.country, row.country_name)

        # Batch geoip lookup for IPs not yet known
        unknown_ips = [
            e.ip for e in entries
            if validate_ip(e.ip) and e.ip not in known_geoip
        ]
        if unknown_ips:
            batch_results = await get_country_codes_batch(list(set(unknown_ips)))
            known_geoip.update(batch_results)

        for entry in entries:
            if not validate_ip(entry.ip):
                continue

            jail = sanitize_jail(entry.jail)
            key = (entry.ip, jail, entry.timestamp, entry.action)

            if key in existing_set:
                continue
            existing_set.add(key)

            country_code, country_name = known_geoip.get(entry.ip, (None, None))

            log_entry = AttackLog(
                ip=entry.ip,
                country=country_code,
                country_name=country_name,
                jail=jail,
                timestamp=entry.timestamp,
                action=entry.action,
                raw_log=entry.raw_log
            )
            session.add(log_entry)

            if country_code:
                await update_country_stats(session, country_code, country_name)

            await update_jail_stats(session, entry.jail, entry.action)

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
@app.websocket("/api/ws")
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
@app.get("/api")
async def root():
    """Root API endpoint."""
    return {"message": "Fail2Ban SOC Dashboard API", "version": "1.0.0"}


@app.get("/api/stats/overview")
async def get_stats_overview(
    days: Optional[int] = Query(None, ge=1)
):
    """
    Get dashboard summary statistics.
    Returns total bans, today, this week, and top countries.
    """
    async with async_session_maker() as session:
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Use provided days or default to 7
        days_value = days if days else 7
        period_start = now - timedelta(days=days_value)
        
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
        
        # Period bans (based on days parameter)
        result = await session.execute(
            select(func.count(AttackLog.id)).where(
                and_(
                    AttackLog.action == "Ban",
                    AttackLog.timestamp >= period_start
                )
            )
        )
        period_bans = result.scalar() or 0
        
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
        
        period_label = f"{days_value} days" if days_value != 36500 else "All time"
        
        return {
            "total_bans": total_bans,
            "today_bans": today_bans,
            "period_bans": period_bans,
            "period_label": period_label,
            "active_bans": active_bans,
            "top_countries": top_countries,
            "jails": jails,
            "timestamp": now.isoformat()
        }


@app.get("/api/stats/attacks-over-time")
async def get_attacks_over_time(
    days: int = Query(7, ge=1, le=36500),
    interval: str = Query("hour", pattern="^(hour|day)$")
):
    """
    Get time series data for attacks over time.
    """
    async with async_session_maker() as session:
        start_date = datetime.now() - timedelta(days=days)
        
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
    limit: int = Query(10, ge=1, le=50),
    days: Optional[int] = Query(None, ge=1)
):
    """
    Get country breakdown of attacks.
    """
    async with async_session_maker() as session:
        conditions = [AttackLog.country.isnot(None)]
        if days:
            conditions.append(AttackLog.timestamp >= datetime.now() - timedelta(days=days))

        query = select(
            AttackLog.country,
            AttackLog.country_name,
            func.count(AttackLog.id).label("total_attacks"),
            func.count(func.distinct(AttackLog.ip)).label("unique_ips")
        ).where(
            and_(*conditions)
        ).group_by(
            AttackLog.country
        ).order_by(
            desc("total_attacks")
        ).limit(limit)

        result = await session.execute(query)
        countries = [
            {
                "country": row.country,
                "country_name": row.country_name,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips
            }
            for row in result
        ]

        return {
            "limit": limit,
            "countries": countries
        }


@app.get("/api/stats/heatmap-data")
async def get_heatmap_data(
    days: Optional[int] = Query(None, ge=1)
):
    """
    Get attack intensity data by country for map visualization.
    """
    async with async_session_maker() as session:
        conditions = [AttackLog.country.isnot(None)]
        if days:
            conditions.append(AttackLog.timestamp >= datetime.now() - timedelta(days=days))

        query = select(
            AttackLog.country,
            AttackLog.country_name,
            func.count(AttackLog.id).label("total_attacks"),
            func.count(func.distinct(AttackLog.ip)).label("unique_ips")
        ).where(
            and_(*conditions)
        ).group_by(
            AttackLog.country
        ).order_by(
            desc("total_attacks")
        )

        result = await session.execute(query)
        rows = result.all()

        max_attacks = rows[0].total_attacks if rows else 1
        heatmap = [
            {
                "country": row.country,
                "country_name": row.country_name,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips,
                "intensity": round((row.total_attacks / max_attacks) * 100, 1)
            }
            for row in rows
        ]

        return {
            "heatmap": heatmap
        }


@app.get("/api/banned-ips")
async def get_banned_ips(
    jail: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    days: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """
    Get list of currently banned IPs.
    """
    async with async_session_maker() as session:
        # Apply time filter
        time_filter = None
        if days:
            time_filter = datetime.now() - timedelta(days=days)
        
        base_conditions = []
        if jail:
            base_conditions.append(BannedIP.jail == sanitize_jail(jail))
        if country:
            base_conditions.append(BannedIP.country == country.upper())
        if time_filter:
            base_conditions.append(BannedIP.ban_timestamp >= time_filter)
        
        if base_conditions:
            query = select(BannedIP).where(and_(*base_conditions)).order_by(desc(BannedIP.ban_timestamp))
        else:
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
    action: Optional[str] = Query(None, pattern="^(Ban|Unban)$"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    Queryable logs with filters.
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
    """Force refresh of data from all logs (including rotated/gzipped)."""
    entries = await parse_all_logs_async()

    if not entries:
        return {"status": "no_entries", "message": "No log entries found"}

    await process_parsed_entries(entries)
    return {"status": "success", "message": f"Processed {len(entries)} log entries"}


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_websockets": len(websocket_connections)
    }


@app.get("/api/stats/system")
async def get_system_stats():
    """
    Get system CPU, memory, swap, disk and other important metrics.
    """
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')
    
    # Uptime in seconds
    import time as _time
    uptime_seconds = int(_time.time() - psutil.boot_time())
    
    # Load average (Linux only, returns 1, 5, 15 min averages)
    try:
        load_avg = psutil.getloadavg()
    except (AttributeError, OSError):
        load_avg = (0.0, 0.0, 0.0)
    
    return {
        "cpu": {
            "percent": cpu_percent,
            "count": psutil.cpu_count(),
            "load_avg": load_avg
        },
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "percent": memory.percent,
            "used": memory.used
        },
        "swap": {
            "total": swap.total,
            "free": swap.free,
            "used": swap.used,
            "percent": swap.percent
        },
        "disk": {
            "total": disk.total,
            "free": disk.free,
            "used": disk.used,
            "percent": disk.percent
        },
        "uptime": uptime_seconds,
        "timestamp": datetime.now().isoformat()
    }

# Serve the static frontend (index.html from root)
@app.get("/")
@app.get("/index.html")
async def serve_index():
    # Use absolute path: index.html is at /var/www/html/perito.digital/dashboard/index.html
    # and this script is at /var/www/html/perito.digital/dashboard/backend/main.py
    index_path = Path(__file__).parent.parent / "index.html"
    return FileResponse(index_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
