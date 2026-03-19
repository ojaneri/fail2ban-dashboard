"""
Fail2Ban log parser module for SOC Dashboard.
Parses various Fail2Ban log formats and extracts relevant information.
"""
import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import asyncio


# Common Fail2Ban log patterns
_PATTERNS = {
    # Standard Fail2Ban ban action with PID and level
    # Example: 2026-03-19 16:00:59,481 fail2ban.actions [7576]: NOTICE [sshd] Ban 159.223.43.21
    "ban": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+"
        r"(?:fail2ban\.\w+\s+)?"
        r"(?:\[(?:\d+)\]:\s+)?"
        r"(?:(?P<level>WARNING|INFO|NOTICE|ERROR|CRITICAL)\s+)?"
        r"\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Ban)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    
    # Standard Fail2Ban unban action with PID and level
    # Example: 2026-03-19 16:10:58,901 fail2ban.actions [7576]: NOTICE [sshd] Unban 159.223.43.21
    "unban": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+"
        r"(?:fail2ban\.\w+\s+)?"
        r"(?:\[(?:\d+)\]:\s+)?"
        r"(?:(?P<level>WARNING|INFO|NOTICE|ERROR|CRITICAL)\s+)?"
        r"\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Unban)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    
    # Fail2Ban with service info (no PID)
    # Example: 2024-01-15 10:30:45 fail2ban.actions: NOTICE sshd: Ban 192.168.1.100
    "ban_alt": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+"
        r"fail2ban\.\w+\s*:\s*"
        r"(?:(?P<level>WARNING|INFO|NOTICE|ERROR|CRITICAL)\s+)?"
        r"(?P<jail>[\w-]+):\s+"
        r"(?P<action>Ban)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    
    # Syslog format
    # Example: Jan 15 10:30:45 hostname fail2ban[1234]: NOTICE [sshd] Ban 192.168.1.100
    "syslog": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+fail2ban\[(?:\d+)\]:\s+"
        r"(?:(?P<level>WARNING|INFO|NOTICE|ERROR|CRITICAL)\s+)?"
        r"\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Ban|Unban)\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    
    # IPv6 pattern
    "ban_ipv6": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+"
        r"(?:fail2ban\.\w+\s+)?"
        r"(?:\[(?:\d+)\]:\s+)?"
        r"(?:(?P<level>WARNING|INFO|NOTICE|ERROR|CRITICAL)\s+)?"
        r"\[(?P<jail>[^\]]+)\]\s+"
        r"(?P<action>Ban)\s+(?P<ip>[a-fA-F0-9:]+)"
    ),
}

# Default log paths to check
DEFAULT_LOG_PATHS = [
    "/var/log/fail2ban.log",
    "/var/log/fail2ban/fail2ban.log",
    "/var/log/fail2ban.log.1",
    "/var/log/fail2ban/fail2ban.log.1",
]


class ParseResult:
    """Container for parsed log entry."""
    def __init__(
        self,
        timestamp: datetime,
        ip: str,
        jail: str,
        action: str,
        raw_log: str,
        level: str = "NOTICE"
    ):
        self.timestamp = timestamp
        self.ip = ip
        self.jail = jail
        self.action = action
        self.raw_log = raw_log
        self.level = level
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "jail": self.jail,
            "action": self.action,
            "level": self.level,
            "raw_log": self.raw_log
        }


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp from various formats.
    
    Args:
        timestamp_str: Timestamp string to parse
        
    Returns:
        datetime object or None if parsing fails
    """
    formats = [
        "%Y-%m-%d %H:%M:%S,%f",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",  # Syslog format (needs year)
        "%Y/%m/%d %H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            # For syslog format, use current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    
    return None


def parse_line(line: str) -> Optional[ParseResult]:
    """
    Parse a single Fail2Ban log line.
    
    Args:
        line: Log line to parse
        
    Returns:
        ParseResult object or None if line doesn't match any pattern
    """
    line = line.strip()
    if not line:
        return None
    
    # Try each pattern
    for pattern_name, pattern in _PATTERNS.items():
        match = pattern.search(line)
        if match:
            groups = match.groupdict()
            
            # Parse timestamp
            timestamp = parse_timestamp(groups.get("timestamp", ""))
            if not timestamp:
                continue
            
            # Get IP
            ip = groups.get("ip", "")
            if not ip:
                continue
            
            # Get jail
            jail = groups.get("jail", "unknown")
            
            # Get action
            action = groups.get("action", "unknown")
            
            # Get level
            level = groups.get("level", "NOTICE")
            
            return ParseResult(
                timestamp=timestamp,
                ip=ip,
                jail=jail,
                action=action,
                raw_log=line,
                level=level
            )
    
    return None


def parse_log_file(log_path: str) -> List[ParseResult]:
    """
    Parse a Fail2Ban log file.
    
    Args:
        log_path: Path to the log file
        
    Returns:
        List of ParseResult objects
    """
    results = []
    
    try:
        path = Path(log_path)
        if not path.exists():
            return results
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                result = parse_line(line)
                if result:
                    results.append(result)
    except (PermissionError, IOError):
        pass
    
    return results


async def parse_log_file_async(log_path: str) -> List[ParseResult]:
    """
    Async version of parse_log_file.
    
    Args:
        log_path: Path to the log file
        
    Returns:
        List of ParseResult objects
    """
    return await asyncio.to_thread(parse_log_file, log_path)


def find_log_path() -> Optional[str]:
    """
    Find an available Fail2Ban log file.
    
    Returns:
        Path to log file or None if not found
    """
    for path_str in DEFAULT_LOG_PATHS:
        path = Path(path_str)
        if path.exists() and path.is_file():
            try:
                # Check if readable
                with open(path, "r") as f:
                    f.read(1)
                return path_str
            except (PermissionError, IOError):
                continue
    return None


def generate_demo_data() -> List[ParseResult]:
    """
    Generate demo data for testing when no log files are available.
    
    Returns:
        List of ParseResult objects with sample data
    """
    import random
    from datetime import timedelta
    
    # Sample IPs by country
    sample_ips = {
        "US": ["192.168.1.100", "10.0.0.50", "172.16.0.25"],
        "CN": ["103.235.46.1", "119.3.102.5", "42.156.137.1"],
        "RU": ["95.173.184.1", "91.236.75.1", "37.143.12.1"],
        "BR": ["177.54.32.1", "189.90.85.1", "200.147.3.1"],
        "DE": ["88.198.44.1", "78.46.86.1", "144.76.68.1"],
        "IN": ["103.255.7.1", "117.102.81.1", "122.176.64.1"],
    }
    
    # Sample jails
    jails = ["sshd", "nginx-http-auth", "nginx-noscript", "apache-auth", "vsftpd"]
    
    results = []
    now = datetime.now()
    
    # Generate 500 sample entries over the past 30 days
    for i in range(500):
        # Random time within past 30 days
        timestamp = now - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Random jail
        jail = random.choice(jails)
        
        # Random country and IP
        country = random.choice(list(sample_ips.keys()))
        ip = random.choice(sample_ips[country])
        
        # Alternate between ban and unban (more bans)
        action = "Ban" if random.random() > 0.3 else "Unban"
        
        # Generate raw log line
        raw_log = (
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} fail2ban.actions "
            f"[1234]: NOTICE [{jail}] {action} {ip}"
        )
        
        results.append(ParseResult(
            timestamp=timestamp,
            ip=ip,
            jail=jail,
            action=action,
            raw_log=raw_log,
            level="NOTICE"
        ))
    
    # Sort by timestamp
    results.sort(key=lambda x: x.timestamp)
    
    return results


def sanitize_ip(ip: str) -> Optional[str]:
    """
    Sanitize and validate an IP address.
    
    Args:
        ip: IP address string
        
    Returns:
        Sanitized IP or None if invalid
    """
    if not ip:
        return None
    
    # Basic validation - should only contain valid IP characters
    ip_pattern = re.compile(r'^[\d.:a-fA-F]+$')
    if not ip_pattern.match(ip):
        return None
    
    # Remove any whitespace
    ip = ip.strip()
    
    # Validate length
    if len(ip) > 45:  # Max IPv6 length
        return None
    
    return ip


def sanitize_jail(jail: str) -> str:
    """
    Sanitize jail name to prevent injection.
    
    Args:
        jail: Jail name string
        
    Returns:
        Sanitized jail name
    """
    if not jail:
        return "unknown"
    
    # Only allow alphanumeric, dash, underscore
    return re.sub(r'[^a-zA-Z0-9_-]', '', jail)
