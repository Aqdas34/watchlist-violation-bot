from curl_cffi import requests
import requests as std_requests  # Standard requests for local VPS calls
import hashlib
import time

import csv
from datetime import datetime, timedelta
from pathlib import Path
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration file path
SHARING_CONFIG_FILE = "sharing_config.json"

# Global config variable (will be loaded dynamically)
_config = None

# === Logging Configuration (Initialize with default first) ===
# Ensure logs directory exists
Path("logs").mkdir(exist_ok=True)

# Initial logging setup - will be reconfigured after config is loaded
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("logs/main.log", encoding='utf-8'),
        logging.StreamHandler()  # Also log to console
    ]
)
logger = logging.getLogger(__name__)


session = std_requests.Session()
session.trust_env = False  # <--- ignores HTTP(S)_PROXY env vars


def _reconfigure_logging():
    """Reconfigure logging with config file settings"""
    config = get_config()
    log_file = config.get("files", {}).get("log_file", "logs/main.log")
    
    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove existing file handler and add new one
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.close()
            root_logger.removeHandler(handler)
    
    # Add new file handler with config file path
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    root_logger.addHandler(file_handler)
    logger.debug(f" Logging reconfigured to use: {log_file}")


# ------------------ Configuration Management ------------------

def load_config():
    """Load configuration from JSON file dynamically"""
    global _config
    try:
        config_path = Path(SHARING_CONFIG_FILE)
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                _config = json.load(f)
            logger.info(f" Configuration loaded from {SHARING_CONFIG_FILE}")
            logger.debug(f"   Files config: {_config.get('files', {})}")
            logger.debug(f"   API URL: {_config.get('api', {}).get('api_url', 'N/A')}")
            return _config
        else:
            logger.warning(f" Config file {SHARING_CONFIG_FILE} not found. Using default values.")
            # Default configuration
            _config = {
                "files": {
                    "csv_file": "emails.csv",
                    "violations_file": "violations.json",
                    "log_file": "logs/main.log"
                },
                "api": {
                    "api_url": "https://member.watchlist-pro.com/api/user/queryInfo/v1",
                    "vps_url": "http://162.19.2262.109:5000/login",
                    "timeout": 20,
                    "vps_timeout": 420
                },
                "email": {
                    "smtp_host": "smtp.hostinger.com",
                    "smtp_port": 465,
                    "smtp_email": "test@whmc.webncodes.space",
                    "smtp_password": "Pucit123@@@",
                    "admin_email": "manoaqdas33@gmail.com",
                    "smtp_timeout": 30
                },
                "violations": {
                    "sharing_threshold": 3,
                    "inactivity_threshold": 1,
                    "inactivity_days": 60,
                    "sharing_days": 30,
                    "cycle_interval_minutes": 20
                },
                "exclusions": {
                    "accounts": ["ark.boss2@arkodeitv.com"],
                    "ips": ["98.251.68.45"],
                    "dids": ["124187073355", "020000000000"]
                },
                "headers": {
                    "Content-Type": "application/json"
                }
            }
            return _config
    except json.JSONDecodeError as e:
        logger.error(f" Error parsing config file {SHARING_CONFIG_FILE}: {e}")
        logger.error("   Using default configuration")
        _config = {
            "files": {
                "csv_file": "emails.csv",
                "violations_file": "violations.json",
                "log_file": "logs/main.log"
            },
            "api": {
                "api_url": "https://member.watchlist-pro.com/api/user/queryInfo/v1",
                "vps_url": "http://162.19.2262.109:5000/login",
                "timeout": 20,
                "vps_timeout": 420
            },
            "email": {
                "smtp_host": "smtp.hostinger.com",
                "smtp_port": 465,
                "smtp_email": "test@whmc.webncodes.space",
                "smtp_password": "Pucit123@@@",
                "admin_email": "manoaqdas33@gmail.com",
                "smtp_timeout": 30
            },
            "violations": {
                "sharing_threshold": 3,
                "inactivity_threshold": 1,
                "inactivity_days": 60,
                "sharing_days": 30,
                "cycle_interval_minutes": 20
            },
            "exclusions": {
                "accounts": ["ark.boss2@arkodeitv.com"],
                "ips": ["98.251.68.45"],
                "dids": ["124187073355", "020000000000"]
            },
            "headers": {
                "Content-Type": "application/json"
            }
        }
        return _config
    except Exception as e:
        logger.error(f" Unexpected error loading config file {SHARING_CONFIG_FILE}: {e}")
        raise


def get_config():
    """Get current configuration, loading it if not already loaded"""
    global _config
    if _config is None:
        load_config()
    return _config




# Initialize configuration on import
get_config()
# Reconfigure logging with config file settings
_reconfigure_logging()


# ------------------ Utilities ------------------

def load_tokens():
    """Load tokens and violation counts from CSV file dynamically"""
    config = get_config()
    csv_file = config.get("files", {}).get("csv_file", "emails.csv")
    logger.debug(f" Loading tokens from: {csv_file}")
    
    tokens = {}
    violation_counts = {}
    if Path(csv_file).exists():
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = row.get("email", "").strip()
                if email:
                    # Strip whitespace from token to avoid issues
                    tokens[email] = row.get("token", "").strip()
                    # Load violation count if exists
                    violation_count = row.get("violation_count", "0").strip()
                    try:
                        violation_counts[email] = int(violation_count) if violation_count else 0
                    except ValueError:
                        violation_counts[email] = 0
        logger.debug(f" Loaded {len(tokens)} token(s) from {csv_file}")
    else:
        logger.warning(f" CSV file not found: {csv_file}")
    return tokens, violation_counts


def save_token(email, token, violation_count=None):
    """Save token and violation count to CSV file dynamically"""
    config = get_config()
    csv_file = config.get("files", {}).get("csv_file", "emails.csv")
    logger.debug(f" Saving token to: {csv_file}")
    
    tokens, violation_counts = load_tokens()
    email_exists = email in tokens
    tokens[email] = token
    
    # Update violation count if provided, otherwise keep existing
    if violation_count is not None:
        violation_counts[email] = violation_count
    elif email not in violation_counts:
        violation_counts[email] = 0

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email", "token", "violation_count"])
        for e in tokens.keys():
            writer.writerow([e, tokens[e], violation_counts.get(e, 0)])
    
    if email_exists:
        logger.info(f" Token updated for {email[:20]}... (email already existed in CSV)")
    else:
        logger.info(f" Token saved for {email[:20]}... (NEW email added to CSV)")


def save_violation_count(email, violation_count):
    """Update only violation count in CSV file"""
    config = get_config()
    csv_file = config.get("files", {}).get("csv_file", "emails.csv")
    logger.debug(f" Updating violation count for {email[:20]}... to {violation_count}")
    
    tokens, violation_counts = load_tokens()
    violation_counts[email] = violation_count

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email", "token", "violation_count"])
        for e in tokens.keys():
            writer.writerow([e, tokens.get(e, ""), violation_counts.get(e, 0)])
    
    logger.debug(f" Violation count updated for {email[:20]}...")


def to_datetime(ms):
    return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def generate_password(email):
    """
    Generate password from email format.
    Email format: ark.username@domain.com
    Password format: arkusernamepass (remove dot, remove @domain, add 'pass')
    """
    # Remove the @domain part
    local_part = email.split('@')[0]
    # Remove dots and add 'pass' at the end
    password = (local_part.replace('.', '') + 'pass').lower()
    return password


def extract_username(email):
    """
    Extract username from email for grouping.
    ark.username@domain.com -> username
    ark.username2@domain.com -> username
    """
    local_part = email.split('@')[0]
    # Remove 'ark.' prefix if present
    if local_part.startswith('ark.'):
        username = local_part[4:]  # Remove 'ark.'
        # Remove trailing numbers (e.g., 'username2' -> 'username')
        # Keep only the base username
        base_username = ''.join([c for c in username if not c.isdigit()])
        return base_username if base_username else username
    return local_part


def load_violations():
    """Load violation history from file dynamically"""
    config = get_config()
    violations_file = config.get("files", {}).get("violations_file", "violations.json")
    logger.debug(f" Loading violations from: {violations_file}")
    
    if Path(violations_file).exists():
        try:
            # Check if file is empty
            file_size = Path(violations_file).stat().st_size
            if file_size == 0:
                logger.info(f" Violations file is empty: {violations_file} - returning empty dict")
                return {}
            
            with open(violations_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                # Check if file content is empty or just whitespace
                if not content:
                    logger.info(f" Violations file is empty: {violations_file} - returning empty dict")
                    return {}
                
                violations = json.loads(content)
                logger.debug(f" Loaded violations for {len(violations)} email(s)")
                return violations
        except json.JSONDecodeError as e:
            logger.warning(f" Invalid JSON in violations file {violations_file}: {e}")
            logger.warning(f"   File may be empty or corrupted. Returning empty dict.")
            return {}
        except Exception as e:
            logger.error(f" Error loading violations from {violations_file}: {e}")
            logger.error(f"   Returning empty dict to continue execution")
            return {}
    else:
        logger.debug(f" Violations file not found: {violations_file} - will be created on first save")
    return {}


def save_violations(violations):
    """Save violation history to file dynamically"""
    config = get_config()
    violations_file = config.get("files", {}).get("violations_file", "violations.json")
    logger.debug(f" Saving violations to: {violations_file}")
    
    try:
        with open(violations_file, 'w', encoding='utf-8') as f:
            json.dump(violations, f, indent=2, ensure_ascii=False)
        logger.debug(f" Violations saved successfully")
    except Exception as e:
        logger.error(f" Error saving violations to {violations_file}: {e}")


def send_email(to_email, subject, body, is_html=False):
    """Send email using SMTP SSL with dynamic configuration"""
    config = get_config()
    email_config = config.get("email", {})
    
    smtp_host = email_config.get("smtp_host", "smtp.hostinger.com")
    smtp_port = email_config.get("smtp_port", 465)
    smtp_email = email_config.get("smtp_email", "test@whmc.webncodes.space")
    smtp_password = email_config.get("smtp_password", "")
    smtp_timeout = email_config.get("smtp_timeout", 30)
    
    logger.debug(f" Email config: host={smtp_host}, port={smtp_port}, from={smtp_email[:10]}...")
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp_email
        msg['To'] = to_email
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        logger.info(f" Sending email to {to_email} via SSL (port {smtp_port})...")
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout) as server:
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
        
        logger.info(f" Email sent successfully to {to_email}")
        return True
    except (smtplib.SMTPException, OSError, TimeoutError) as e:
        logger.error(f" Failed to send email to {to_email}: {e}")
        logger.error(f"   Please check:")
        logger.error(f"   1. SMTP server settings (host: {smtp_host}, port: {smtp_port})")
        logger.error(f"   2. Firewall/network restrictions")
        logger.error(f"   3. Email credentials")
        logger.error(f"   4. Internet connection")
        return False
    except Exception as e:
        logger.error(f" Unexpected error sending email to {to_email}: {e}")
        return False


# ------------------ API Calls ------------------

def call_with_token(token):
    """Call API with token using dynamic configuration"""
    config = get_config()
    api_config = config.get("api", {})
    
    api_url = api_config.get("api_url", "https://member.watchlist-pro.com/api/user/queryInfo/v1")
    timeout = api_config.get("timeout", 20)
    
    headers = {
        "Authorization": token,
        "client-type": "WEB",
        "content-type": "application/json;charset=UTF-8",
        "accept": "application/json"
    }

    try:
        token_preview = token[:50] + "..." if len(token) > 50 else token
        logger.info(f" Calling API with token: {token_preview}")
        logger.debug(f"   API URL: {api_url}")
        logger.debug(f"   Timeout: {timeout}s")
        # Use standard requests instead of curl_cffi for better compatibility
        resp = session.post(
            api_url,
            headers=headers,
            json={},      # required by this API
            timeout=timeout
        )
        logger.info(f" Response status: {resp.status_code}")

        # If Cloudflare rate limits (HTTP 429), wait 5 minutes and retry once
        if resp.status_code == 429:
            logger.warning(" Received 429 (rate limited). Waiting 5 minutes before retrying...")
            time.sleep(300)  # 5 minutes
            resp = session.post(
                api_url,
                headers=headers,
                json={},
                timeout=timeout
            )
            logger.info(f" Retry response status: {resp.status_code}")

        resp.raise_for_status()
        result = resp.json()
        logger.info(f" API call successful: {result.get('successful', 'N/A')}")
        return result   # ← ONLY JSON

    except std_requests.exceptions.HTTPError as e:
        logger.error(f" HTTP Error: {e}")
        logger.error(f"   Response status: {resp.status_code}")
        logger.error(f"   Response body: {resp.text}")
        return None
    except std_requests.exceptions.RequestException as e:
        logger.error(f" Request Error: {e}")
        return None
    except Exception as e:
        logger.error(f" Unexpected Error: {e}")
        return None

def call_vps(email):
    """Call VPS API with dynamic configuration"""
    config = get_config()
    api_config = config.get("api", {})
    headers_config = config.get("headers", {})
    
    vps_url = api_config.get("vps_url", "http://162.19.2262.109:5000/login")
    vps_timeout = api_config.get("vps_timeout", 420)
    headers = headers_config.copy()  # Use headers from config
    
    try:
        # Generate password for emails starting with "ark"
        if email.startswith("ark"):
            password = generate_password(email)
        else:
            password = "123123"

        
        payload = {
            "email": email,
            "password": password
        }
        logger.info(f" Calling VPS for email: {email}")
        logger.debug(f"   VPS URL: {vps_url}")
        logger.debug(f"   Generated password: {password}")
        logger.debug(f"   Timeout: {vps_timeout}s")
        # Use standard requests instead of curl_cffi for better compatibility
        r = session.post(vps_url, json=payload, headers=headers, timeout=vps_timeout)
        r.raise_for_status()
        logger.info(f" VPS call successful for {email}")
        return r.json()
    except std_requests.exceptions.HTTPError as e:
        logger.error(f" VPS HTTP Error for {email}: {e}")
        logger.error(f"   Response status: {r.status_code}")
        logger.error(f"   Response body: {r.text}")
        raise
    except std_requests.exceptions.RequestException as e:
        logger.error(f" VPS Request Error for {email}: {e}")
        raise
    except Exception as e:
        logger.error(f" VPS Unexpected Error for {email}: {e}")
        raise



def check_inactivity_violation(account_devices):
    """
    Check for inactivity violation: hasn't been used within configured days or never logged in
    Returns: (is_violation, details)
    """
    config = get_config()
    inactivity_days = config.get("violations", {}).get("inactivity_days", 60)
    
    now = datetime.now()
    threshold_date = now - timedelta(days=inactivity_days)
    
    violations = []
    for device in account_devices:
        last_login_ms = device.get("lastLoginDate")
        if not last_login_ms:
            # Never logged in
            violations.append({
                "device": device,
                "reason": "Never logged in"
            })
        else:
            # Convert milliseconds to datetime
            last_login = datetime.fromtimestamp(last_login_ms / 1000)
            if last_login < threshold_date:
                violations.append({
                    "device": device,
                    "reason": f"Last login: {last_login.strftime('%Y-%m-%d %H:%M:%S')} (more than {inactivity_days} days ago)"
                })
    
    if violations:
        return True, {"violations": violations}
    
    return False, None


def check_group_sharing_violation(group_accounts_data):
    """
    Check for sharing violation across all accounts in a username group
    Sharing Rule 1: Different IPs on any account in a group within the last 30 days
    (every account in the group should have the same IP)
    Returns: (is_violation, details)
    """

    config = get_config()
    # Get exclusions from config, defaulting to empty lists if not found
    exclusions = config.get("exclusions", {})
    excluded_accounts = set(exclusions.get("accounts", []))
    excluded_ips = set(exclusions.get("ips", []))
    excluded_dids = set(exclusions.get("dids", []))
    
    # Get sharing days threshold (default 30 days)
    sharing_days = config.get("violations", {}).get("sharing_days", 30)
    now = datetime.now()
    threshold_date = now - timedelta(days=sharing_days)

    logger.debug(f"Excluded Accounts: {excluded_accounts}")
    logger.debug(f"Excluded IPs: {excluded_ips}")
    logger.debug(f"Excluded DIDs: {excluded_dids}")
    logger.debug(f"Sharing rule time window: last {sharing_days} days (since {threshold_date.strftime('%Y-%m-%d %H:%M:%S')})")

    all_devices = []
    account_ips = defaultdict(set)
    
    for email, devices in group_accounts_data.items():
        # Skip excluded accounts
        if email in excluded_accounts:
            logger.debug(f" [Exclusion] Skipping account {email}: account is whitelisted.")
            continue
            
        for device in devices:
            ip = device.get("lastLoginClientIp")
            did = device.get("did")
            last_login_ms = device.get("lastLoginDate")

            # Check if device was used within the last 30 days
            if last_login_ms:
                last_login = datetime.fromtimestamp(last_login_ms / 1000)
                if last_login < threshold_date:
                    logger.debug(f" [Time Filter] Skipping device for {email}: last login {last_login.strftime('%Y-%m-%d %H:%M:%S')} is more than {sharing_days} days ago.")
                    continue
            else:
                # Never logged in - skip for sharing rule (only check devices with login history)
                logger.debug(f" [Time Filter] Skipping device for {email}: never logged in.")
                continue

            if ip and ip in excluded_ips:
                logger.debug(f" [Exclusion] Skipping device for {email}: IP {ip} is whitelisted.")
                continue
            if did and did in excluded_dids:
                logger.debug(f" [Exclusion] Skipping device for {email}: DID {did} is whitelisted.")
                continue

            all_devices.append({
                **device,
                "email": email
            })
            if ip:
                account_ips[email].add(ip)
    
    if len(all_devices) <= 1:
        return False, None
    
    # Check if there are different IPs across the group
    all_ips = set()
    for ips in account_ips.values():
        all_ips.update(ips)
    
    if len(all_ips) > 1:
        details = {
            "total_devices": len(all_devices),
            "unique_ips": list(all_ips),
            "account_ips": {email: list(ips) for email, ips in account_ips.items()},
            "devices": all_devices,
            "rule": "Sharing Rule 1: Different IPs in group within last 30 days"
        }
        return True, details
    
    return False, None


def check_account_sharing_violation(email, devices):
    """
    Check for sharing violation on a single account
    Sharing Rule 2: Multiple devices under the same account
    (each account should only have 1 device logged in within the last 30 days)
    Returns: (is_violation, details)
    """
    config = get_config()
    # Get exclusions from config
    exclusions = config.get("exclusions", {})
    excluded_accounts = set(exclusions.get("accounts", []))
    excluded_ips = set(exclusions.get("ips", []))
    excluded_dids = set(exclusions.get("dids", []))
    
    # Skip excluded accounts
    if email in excluded_accounts:
        logger.debug(f" [Exclusion] Skipping account {email}: account is whitelisted.")
        return False, None
    
    # Get sharing days threshold (default 30 days)
    sharing_days = config.get("violations", {}).get("sharing_days", 30)
    now = datetime.now()
    threshold_date = now - timedelta(days=sharing_days)

    logger.debug(f"Checking account-level sharing for {email} (last {sharing_days} days)")
    
    # Filter devices by time window and exclusions
    recent_devices = []
    for device in devices:
        ip = device.get("lastLoginClientIp")
        did = device.get("did")
        last_login_ms = device.get("lastLoginDate")

        # Check if device was used within the last 30 days
        if last_login_ms:
            last_login = datetime.fromtimestamp(last_login_ms / 1000)
            if last_login < threshold_date:
                logger.debug(f" [Time Filter] Skipping device: last login {last_login.strftime('%Y-%m-%d %H:%M:%S')} is more than {sharing_days} days ago.")
                continue
        else:
            # Never logged in - skip for sharing rule
            logger.debug(f" [Time Filter] Skipping device: never logged in.")
            continue

        if ip and ip in excluded_ips:
            logger.debug(f" [Exclusion] Skipping device: IP {ip} is whitelisted.")
            continue
        if did and did in excluded_dids:
            logger.debug(f" [Exclusion] Skipping device: DID {did} is whitelisted.")
            continue

        recent_devices.append(device)
    
    # Check if there are multiple devices on this account within the last 30 days
    if len(recent_devices) > 1:
        details = {
            "account": email,
            "device_count": len(recent_devices),
            "devices": recent_devices,
            "rule": "Sharing Rule 2: Multiple devices on same account within last 30 days"
        }
        return True, details
    
    return False, None


# ------------------ Main Logic ------------------

def get_account_data(email, stored_tokens):
    """
    Get account data (devices) for a single email
    Args:
        email: Email in ark format (e.g., ark.username@domain.com)
        stored_tokens: Dictionary of stored tokens
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"Processing: {email}")
    token = stored_tokens.get(email)
    data = None

    if token:
        logger.info(f"✓ Token found for {email}")
        api_response = call_with_token(token)
        if api_response:
            logger.info(f"Response data keys: {list(api_response.keys())}")
            logger.info(f"Response successful: {api_response.get('successful', 'N/A')}")
            logger.info(f"Response errCode: {api_response.get('errCode', 'N/A')}")
            
            # Check if API call was successful
            if api_response.get("successful") or api_response.get("errCode") == 0:
                # API response structure: {retCode, errCode, message, data: {userDevice: [...]}, successful}
                # Wrap it to match VPS response structure: {userInfo: {data: {...}}}
                data = {
                    "userInfo": {
                        "data": api_response.get("data", {})
                    }
                }
            else:
                logger.warning(f" API call returned error: {api_response.get('message', 'Unknown error')}")
                data = None
        else:
            logger.warning(" No data returned from API call")
            data = None

    # If token missing OR invalid OR error
    if not data or not data.get("userInfo"):
        logger.info("→ Fetching token via VPS (token missing or API call failed)")
        try:
            logger.debug(f"   Using email for VPS call: {email}")
            vps_resp = call_vps(email)
            # Extract token from VPS response: vps_resp["data"]["token"]
            if vps_resp.get("successful") and vps_resp.get("data", {}).get("token"):
                token = vps_resp["data"]["token"]
                # Save token with ark email format (not original email)
                save_token(email, token)  # Save with ark email format
                logger.info(f"✓ Token extracted and saved for {email}")
                
                # Now call queryInfo API with the token (like app.py:526-559)
                headers = {
                    "Authorization": token,
                    "client-type": "WEB",
                    "content-type": "application/json;charset=UTF-8",
                    "accept": "application/json"
                }
                
                try:
                    config = get_config()
                    api_config = config.get("api", {})
                    api_url = api_config.get("api_url", "https://member.watchlist-pro.com/api/user/queryInfo/v1")
                    timeout = api_config.get("timeout", 20)
                    
                    logger.info(f" Calling queryInfo API with token for {email}")
                    logger.debug(f"   API URL: {api_url}")
                    logger.debug(f"   Timeout: {timeout}s")
                    # Use standard requests instead of curl_cffi for better compatibility
                    resp = session.post(
                        api_url,
                        headers=headers,
                        json={},
                        timeout=timeout
                    )
                    resp.raise_for_status()
                    user_info = resp.json()
                    logger.info(f" queryInfo API call successful for {email}")
                    
                    # Return structure similar to app.py:554-558
                    data = {
                        "success": True,
                        "token": token,
                        "userInfo": user_info
                    }
                except Exception as e:
                    logger.warning(f" queryInfo API call failed for {email}: {e}")
                    # Return structure with warning (like app.py:546-552)
                    data = {
                        "success": True,
                        "token": token,
                        "warning": "Login OK, queryInfo failed",
                        "error": str(e),
                        "userInfo": None
                    }
            else:
                logger.error(f" VPS response missing token for {email}")
                logger.error(f"   VPS response: {vps_resp}")
                return None
        except Exception as e:
            logger.error(f" VPS call failed: {e}")
            return None

    # Extract device info
    user_info = data.get("userInfo")
    
    if not user_info:
        logger.warning(f" No userInfo found for {email}")
        return None
    
    # userInfo is the queryInfo API response: {retCode, errCode, message, data: {userDevice: [...]}, successful}
    if isinstance(user_info, dict) and "data" in user_info:
        user_data = user_info["data"]
    else:
        user_data = {}
    
    devices = user_data.get("userDevice", [])
    
    if not devices:
        logger.warning(f" No devices found for {email}")
        return []
    
    logger.info(f" Found {len(devices)} device(s) for {email}")
    
    # Return list of devices with email attached
    device_list = []
    for device in devices:
        device_info = {
            "email": email,
            "did": device.get("did"),
            "lastLoginClientIp": device.get("lastLoginClientIp"),
            "lastLoginDate": device.get("lastLoginDate")
        }
        device_list.append(device_info)
        logger.info(f" Device: {device_info}")
    
    return device_list


def process_emails(email_list):
    """
    Process emails for violation checking
    Args:
        email_list: List of emails to process (ark format, e.g., ark.username@domain.com)
    """
    stored_tokens, violation_counts = load_tokens()
    logger.info(f"Loaded tokens for {len(stored_tokens)} email(s): {list(stored_tokens.keys())}")
    
    # Step 1: Sort and group emails by username (before fetching account data)
    logger.info(f"\n{'='*60}")
    logger.info(" Step 1: Sorting and grouping emails by username...")
    
    # Sort emails first
    sorted_emails = sorted(email_list)
    logger.info(f" Sorted {len(sorted_emails)} email(s)")
    
    # Group emails by username (without fetching account data yet)
    username_groups = defaultdict(list)  # username -> [list of emails]
    for email in sorted_emails:
        username = extract_username(email)
        username_groups[username].append(email)
        logger.info(f" Grouped {email} under username: {username}")
    
    logger.info(f"✓ Grouped into {len(username_groups)} username group(s)")
    
    # Step 2: Load violation history once (will be updated after each group)
    violations_history = load_violations()
    
    # Step 3: Process each group completely (fetch data, check violations, send emails, save) before moving to next
    logger.info(f"\n{'='*60}")
    logger.info(" Step 2: Processing groups (fetching data, checking violations, sending emails)...")
    
    group_number = 0
    for username, group_emails in username_groups.items():
        group_number += 1
        logger.info(f"\n{'='*60}")
        logger.info(f" Processing Group {group_number}/{len(username_groups)}: {username}")
        logger.info(f" Emails in group: {group_emails}")
        logger.info(f"{'='*60}")
        
        # Step 3a: Fetch account data for all emails in this group
        logger.info(f" Fetching account data for {len(group_emails)} email(s) in group '{username}'...")
        group_accounts_data = {}  # email -> list of devices
        for email in group_emails:
            devices = get_account_data(email, stored_tokens)
            if devices is not None:
                group_accounts_data[email] = devices
            else:
                logger.warning(f" Failed to fetch account data for {email}")
        
        if not group_accounts_data:
            logger.warning(f" No account data collected for group '{username}'. Skipping to next group.")
            continue
        
        logger.info(f"✓ Fetched account data for {len(group_accounts_data)} email(s) in group '{username}'")
        
        # Step 3b: Check violations for this group
        logger.info(f" Checking violations for group '{username}'...")
        
        # Check group-level sharing violation (sharing rule applies across all accounts in the group)
        is_group_sharing, group_sharing_details = check_group_sharing_violation(group_accounts_data)
        
        # Check each account for violations
        for email, devices in group_accounts_data.items():
            # Initialize violation tracking for this email
            if email not in violations_history:
                # Initialize with count from CSV if available
                csv_count = violation_counts.get(email, 0)
                violations_history[email] = {
                    "sharing": {
                        "count": csv_count,
                        "last_violation_time": None,
                        "details": None
                    },
                    "inactivity": {
                        "count": 0,
                        "last_violation_time": None,
                        "details": None,
                        "email_sent": False
                    }
                }
            else:
                # Sync count from CSV if available
                csv_count = violation_counts.get(email, 0)
                if csv_count > 0 and violations_history[email]["sharing"].get("count", 0) != csv_count:
                    violations_history[email]["sharing"]["count"] = csv_count
                    logger.debug(f"   Synced violation count from CSV for {email}: {csv_count}")
            
            config = get_config()
            
            # Check both sharing rules
            # Rule 1: Group-level sharing (different IPs in group within last 30 days)
            # Rule 2: Account-level sharing (multiple devices on same account within last 30 days)
            is_account_sharing, account_sharing_details = check_account_sharing_violation(email, devices)
            
            # Determine if there's any sharing violation (either rule)
            is_sharing_violation = is_group_sharing or is_account_sharing
            
            if is_sharing_violation:
                sharing_data = violations_history[email]["sharing"]
                
                # Get current count from CSV (source of truth)
                current_count = violation_counts.get(email, sharing_data.get("count", 0))
                new_count = current_count + 1
                
                # Determine which rule was violated and combine details
                violation_details = None
                violation_rule = None
                
                if is_group_sharing and is_account_sharing:
                    # Both rules violated
                    violation_rule = "Both Sharing Rule 1 and Rule 2"
                    violation_details = {
                        "rule": violation_rule,
                        "group_violation": group_sharing_details,
                        "account_violation": account_sharing_details,
                        "unique_ips": group_sharing_details.get('unique_ips', []),
                        "device_count": account_sharing_details.get('device_count', 0)
                    }
                    logger.warning(f" SHARING VIOLATION (BOTH RULES) detected for {email} (Count: {new_count})")
                    logger.warning(f"   Rule 1: {len(group_sharing_details.get('unique_ips', []))} unique IPs across group")
                    logger.warning(f"   Rule 2: {account_sharing_details.get('device_count', 0)} devices on account")
                elif is_group_sharing:
                    # Only Rule 1 violated
                    violation_rule = group_sharing_details.get('rule', 'Sharing Rule 1')
                    violation_details = group_sharing_details
                    logger.warning(f" SHARING VIOLATION (Rule 1) detected for {email} (Count: {new_count})")
                    logger.warning(f"   Group violation: {len(group_sharing_details.get('unique_ips', []))} unique IPs across group")
                elif is_account_sharing:
                    # Only Rule 2 violated
                    violation_rule = account_sharing_details.get('rule', 'Sharing Rule 2')
                    violation_details = account_sharing_details
                    logger.warning(f" SHARING VIOLATION (Rule 2) detected for {email} (Count: {new_count})")
                    logger.warning(f"   Account violation: {account_sharing_details.get('device_count', 0)} devices on account")
                
                # Update violation data
                sharing_data["count"] = new_count
                sharing_data["last_violation_time"] = datetime.now().isoformat()
                sharing_data["details"] = violation_details
                
                # Update violation count in CSV (source of truth)
                save_violation_count(email, new_count)
                
                # Check if threshold reached and send email
                sharing_threshold = config.get("violations", {}).get("sharing_threshold", 3)
                if new_count >= sharing_threshold:
                    logger.error(f" TRIGGER: {email} has {new_count} sharing violations! (threshold: {sharing_threshold})")
                    send_violation_email(email, "sharing", violation_details, new_count)
                    send_violation_email("manoaqdas50@gmail.com", "sharing", violation_details, new_count)
            else:
                # No violation - reset count
                old_count = violation_counts.get(email, violations_history[email]["sharing"].get("count", 0))
                if old_count > 0:
                    logger.info(f" No sharing violation for {email} - resetting count from {old_count} to 0")
                    # Update CSV with reset count
                    save_violation_count(email, 0)
                violations_history[email]["sharing"] = {
                    "count": 0,
                    "last_violation_time": None,
                    "details": None
                }
            
            # Handle inactivity violation (account-level)
            is_inactivity, inactivity_details = check_inactivity_violation(devices)
            if is_inactivity:
                inactivity_data = violations_history[email]["inactivity"]
                
                # For inactivity, send email immediately on first detection (threshold = 1)
                if not inactivity_data.get("email_sent", False):
                    inactivity_data["count"] = 1
                    inactivity_data["last_violation_time"] = datetime.now().isoformat()
                    inactivity_data["details"] = inactivity_details
                    inactivity_data["email_sent"] = True
                    
                    logger.warning(f" INACTIVITY VIOLATION detected for {email}")
                    for v in inactivity_details.get("violations", []):
                        logger.warning(f"   {v['reason']}")
                    
                    # Send email immediately (threshold = 1)
                    inactivity_threshold = config.get("violations", {}).get("inactivity_threshold", 1)
                    logger.error(f" TRIGGER: {email} has inactivity violation! (threshold: {inactivity_threshold})")
                    send_violation_email(email, "inactivity", inactivity_details, 1)
                    send_violation_email("manoaqdas50@gmail.com", "inactivity", inactivity_details, 1)
                else:
                    logger.info(f" Inactivity violation still exists for {email}, but email already sent")
            else:
                # No inactivity violation - reset
                if violations_history[email]["inactivity"].get("count", 0) > 0:
                    logger.info(f" No inactivity violation for {email} - resetting")
                violations_history[email]["inactivity"] = {
                    "count": 0,
                    "last_violation_time": None,
                    "details": None,
                    "email_sent": False
                }
        
        # Step 3c: Save violation history after processing each group
        save_violations(violations_history)
        logger.info(f"\n✓ Group '{username}' processed completely. Violations saved. Emails sent if needed.")
        logger.info(f"  Moving to next group...\n")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✓ All {len(username_groups)} group(s) processed. Violation check complete.")
    logger.info(f"{'='*60}")


def format_details_for_admin(details, violation_type):
    """Format details with proper date formatting for admin email"""
    if not details:
        return details
    
    formatted = details.copy()
    
    if violation_type == "sharing":
        # Handle both rules or single rule
        if "group_violation" in formatted and "account_violation" in formatted:
            # Both rules violated - format both
            if "devices" in formatted["group_violation"]:
                formatted_devices = []
                for device in formatted["group_violation"]["devices"]:
                    formatted_device = device.copy()
                    if "lastLoginDate" in formatted_device and formatted_device["lastLoginDate"]:
                        formatted_device["lastLoginDate"] = to_datetime(formatted_device["lastLoginDate"]) if isinstance(formatted_device["lastLoginDate"], (int, float)) else formatted_device["lastLoginDate"]
                    else:
                        formatted_device["lastLoginDate"] = "Never"
                    formatted_devices.append(formatted_device)
                formatted["group_violation"]["devices"] = formatted_devices
            
            if "devices" in formatted["account_violation"]:
                formatted_devices = []
                for device in formatted["account_violation"]["devices"]:
                    formatted_device = device.copy()
                    if "lastLoginDate" in formatted_device and formatted_device["lastLoginDate"]:
                        formatted_device["lastLoginDate"] = to_datetime(formatted_device["lastLoginDate"]) if isinstance(formatted_device["lastLoginDate"], (int, float)) else formatted_device["lastLoginDate"]
                    else:
                        formatted_device["lastLoginDate"] = "Never"
                    formatted_devices.append(formatted_device)
                formatted["account_violation"]["devices"] = formatted_devices
        elif "devices" in formatted:
            # Single rule - format devices
            formatted_devices = []
            for device in formatted["devices"]:
                formatted_device = device.copy()
                if "lastLoginDate" in formatted_device and formatted_device["lastLoginDate"]:
                    formatted_device["lastLoginDate"] = to_datetime(formatted_device["lastLoginDate"]) if isinstance(formatted_device["lastLoginDate"], (int, float)) else formatted_device["lastLoginDate"]
                else:
                    formatted_device["lastLoginDate"] = "Never"
                formatted_devices.append(formatted_device)
            formatted["devices"] = formatted_devices
    
    elif violation_type == "inactivity":
        # Format violations with readable dates
        if "violations" in formatted:
            formatted_violations = []
            for violation in formatted["violations"]:
                formatted_violation = violation.copy()
                if "device" in formatted_violation:
                    formatted_device = formatted_violation["device"].copy()
                    if "lastLoginDate" in formatted_device and formatted_device["lastLoginDate"]:
                        formatted_device["lastLoginDate"] = to_datetime(formatted_device["lastLoginDate"])
                    else:
                        formatted_device["lastLoginDate"] = "Never"
                    formatted_violation["device"] = formatted_device
                formatted_violations.append(formatted_violation)
            formatted["violations"] = formatted_violations
    
    return formatted


def send_violation_email(email, violation_type, details, count):
    """Send violation notification email"""
    if violation_type == "sharing":
        subject = f"Account Sharing Violation Alert - {email}"
        
        # Determine which rule(s) were violated
        rule = details.get('rule', 'Sharing Violation')
        has_group_violation = 'group_violation' in details
        has_account_violation = 'account_violation' in details
        
        body = f"""
        <html>
        <body>
        <h2>Account Sharing Violation Detected</h2>
        <p>Dear User,</p>
        <p>We have detected a sharing violation on your account: <strong>{email}</strong></p>
        <p><strong>Violation Count:</strong> {count} consecutive violation(s)</p>
        <p><strong>Violation Rule:</strong> {rule}</p>
        """
        
        # Handle both rules or single rule
        if has_group_violation and has_account_violation:
            # Both rules violated
            group_details = details.get('group_violation', {})
            account_details = details.get('account_violation', {})
            
            body += f"""
        <h3>Violation Details:</h3>
        <ul>
            <li><strong>Rule 1 - Group Sharing:</strong> Different IPs across accounts in group</li>
            <li><strong>Unique IP Addresses:</strong> {', '.join(group_details.get('unique_ips', []))}</li>
            <li><strong>Rule 2 - Account Sharing:</strong> Multiple devices on same account</li>
            <li><strong>Device Count:</strong> {account_details.get('device_count', 'N/A')}</li>
        </ul>
        
        <h3>Group Devices (Rule 1):</h3>
        <table border="1" cellpadding="5">
        <tr>
            <th>Email</th>
            <th>Device ID</th>
            <th>IP Address</th>
            <th>Last Login</th>
        </tr>
        """
            for device in group_details.get('devices', []):
                last_login = device.get('lastLoginDate')
                if last_login:
                    last_login_str = to_datetime(last_login) if isinstance(last_login, (int, float)) else last_login
                else:
                    last_login_str = "Never"
                body += f"""
        <tr>
            <td>{device.get('email', 'N/A')}</td>
            <td>{device.get('did', 'N/A')}</td>
            <td>{device.get('lastLoginClientIp', 'N/A')}</td>
            <td>{last_login_str}</td>
        </tr>
        """
            body += """
        </table>
        
        <h3>Account Devices (Rule 2):</h3>
        <table border="1" cellpadding="5">
        <tr>
            <th>Device ID</th>
            <th>IP Address</th>
            <th>Last Login</th>
        </tr>
        """
            for device in account_details.get('devices', []):
                last_login = device.get('lastLoginDate')
                if last_login:
                    last_login_str = to_datetime(last_login) if isinstance(last_login, (int, float)) else last_login
                else:
                    last_login_str = "Never"
                body += f"""
        <tr>
            <td>{device.get('did', 'N/A')}</td>
            <td>{device.get('lastLoginClientIp', 'N/A')}</td>
            <td>{last_login_str}</td>
        </tr>
        """
            body += """
        </table>
        """
        elif has_group_violation or 'unique_ips' in details:
            # Only Rule 1 (group sharing)
            body += f"""
        <h3>Violation Details:</h3>
        <ul>
            <li><strong>Total Devices:</strong> {details.get('total_devices', 'N/A')}</li>
            <li><strong>Unique IP Addresses:</strong> {', '.join(details.get('unique_ips', []))}</li>
        </ul>
        
        <h3>Device Information:</h3>
        <table border="1" cellpadding="5">
        <tr>
            <th>Email</th>
            <th>Device ID</th>
            <th>IP Address</th>
            <th>Last Login</th>
        </tr>
        """
            for device in details.get('devices', []):
                last_login = device.get('lastLoginDate')
                if last_login:
                    last_login_str = to_datetime(last_login) if isinstance(last_login, (int, float)) else last_login
                else:
                    last_login_str = "Never"
                body += f"""
        <tr>
            <td>{device.get('email', 'N/A')}</td>
            <td>{device.get('did', 'N/A')}</td>
            <td>{device.get('lastLoginClientIp', 'N/A')}</td>
            <td>{last_login_str}</td>
        </tr>
        """
            body += """
        </table>
        """
        else:
            # Only Rule 2 (account sharing)
            body += f"""
        <h3>Violation Details:</h3>
        <ul>
            <li><strong>Device Count:</strong> {details.get('device_count', 'N/A')}</li>
        </ul>
        
        <h3>Device Information:</h3>
        <table border="1" cellpadding="5">
        <tr>
            <th>Device ID</th>
            <th>IP Address</th>
            <th>Last Login</th>
        </tr>
        """
            for device in details.get('devices', []):
                last_login = device.get('lastLoginDate')
                if last_login:
                    last_login_str = to_datetime(last_login) if isinstance(last_login, (int, float)) else last_login
                else:
                    last_login_str = "Never"
                body += f"""
        <tr>
            <td>{device.get('did', 'N/A')}</td>
            <td>{device.get('lastLoginClientIp', 'N/A')}</td>
            <td>{last_login_str}</td>
        </tr>
        """
            body += """
        </table>
        """
        
        body += """
        <p>Please ensure that your account is not being shared with others. Multiple IP addresses or multiple devices indicate account sharing, which violates our terms of service.</p>
        <p>If you have any questions, please contact our support team.</p>
        <p>Best regards,<br>WatchList Pro Team</p>
        </body>
        </html>
        """
    else:  # inactivity
        subject = f"Account Inactivity Alert - {email}"
        body = f"""
        <html>
        <body>
        <h2>Account Inactivity Detected</h2>
        <p>Dear User,</p>
        <p>We have detected inactivity on your account: <strong>{email}</strong></p>
        
        <h3>Inactivity Details:</h3>
        <ul>
        """
        for violation in details.get('violations', []):
            device = violation.get('device', {})
            last_login = device.get('lastLoginDate')
            if last_login:
                last_login_str = to_datetime(last_login)
            else:
                last_login_str = "Never"
            body += f"""
            <li>
                <strong>Device ID:</strong> {device.get('did', 'N/A')}<br>
                <strong>Reason:</strong> {violation.get('reason', 'N/A')}<br>
                <strong>Last Login:</strong> {last_login_str}
            </li>
            """
        body += """
        </ul>
        <p>Your account has not been used within the last 2 months. Please log in to maintain your account active.</p>
        <p>If you have any questions, please contact our support team.</p>
        <p>Best regards,<br>WatchList Pro Team</p>
        </body>
        </html>
        """
    
    # Send email to user
    # send_email(email, subject, body, is_html=True)
    
    # Also send notification to admin
    config = get_config()
    admin_email = config.get("email", {}).get("admin_email", "manoaqdas33@gmail.com")
    
    admin_subject = f"[Admin Alert] {violation_type.upper()} Violation - {email}"
    
    # Format details with proper date formatting for admin email
    formatted_details = format_details_for_admin(details, violation_type)
    
    admin_body = f"""
    <html>
    <body>
    <h2>Admin Alert: {violation_type.upper()} Violation</h2>
    <p><strong>Account:</strong> {email}</p>
    <p><strong>Violation Type:</strong> {violation_type}</p>
    <p><strong>Consecutive Count:</strong> {count}</p>
    <p><strong>Details:</strong></p>
    <pre>{json.dumps(formatted_details, indent=2, ensure_ascii=False)}</pre>
    </body>
    </html>
    """
    logger.debug(f" Sending admin notification to: {admin_email}")
    send_email(admin_email, admin_subject, admin_body, is_html=True)
    send_email("manoaqdas33@gmail.com", admin_subject, admin_body, is_html=True)



class FamilyCinemaAPI:
    # Configuration file path
    CONFIG_FILE = "family_cinema_config.json"
    
    def __init__(self, auth_token: str = None, email: str = None, password: str = None):
        logger.info(" Initializing FamilyCinemaAPI...")
        
        # Load configuration from file
        self._load_config()
        
        # Store auth_token from parameters or config file
        # Track if it came from parameters to prevent overriding during reload
        if auth_token:
            self.auth_token = (
                auth_token[6:].strip()
                if auth_token.lower().startswith("bearer")
                else auth_token
            )
            self._auth_token_from_param = True
            logger.info(f" Using auth_token from parameter: {self.auth_token[:20]}...")
        else:
            config_token = self.config.get("auth_token", "")
            if config_token:
                self.auth_token = (
                    config_token[6:].strip()
                    if config_token.lower().startswith("bearer")
                    else config_token
                )
                self._auth_token_from_param = False
                logger.info(f" Using auth_token from config file: {self.auth_token[:20]}...")
            else:
                logger.warning(" No auth_token provided in parameters or config file")
                logger.warning("   You may need to set auth_token in config file or provide it as parameter")
                self.auth_token = None
                self._auth_token_from_param = False
        
        # Store email and password from parameters or config file
        # Track if they came from parameters to prevent overriding during reload
        if email:
            self.email = email
            self._email_from_param = True
            logger.info(f" Using email from parameter: {email[:10]}...")
        else:
            self.email = self.config.get("email", "")
            self._email_from_param = False
            if self.email:
                logger.info(f" Using email from config file: {self.email[:10]}...")
            else:
                logger.warning(" No email provided in parameters or config file")
        
        if password:
            self.password = password
            self._password_from_param = True
            logger.info(" Using password from parameter")
        else:
            self.password = self.config.get("password", "")
            self._password_from_param = False
            if self.password:
                logger.info(" Using password from config file")
            else:
                logger.warning(" No password provided in parameters or config file")
        
        # Check if auth_token is available before initializing session
        if not self.auth_token:
            logger.warning(" No auth_token available. Session will be initialized without token.")
            logger.warning("   You may need to set auth_token in config file or refresh token later.")
        
        # Initialize session and headers
        self._initialize_session()

    def _save_config(self):
        """Save current configuration back to JSON file"""
        try:
            config_path = Path(self.CONFIG_FILE)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.debug(f" Configuration saved to {self.CONFIG_FILE}")
            return True
        except Exception as e:
            logger.error(f" Error saving config file {self.CONFIG_FILE}: {e}")
            return False

    def _load_config(self):
        """Load configuration from JSON file dynamically"""
        try:
            config_path = Path(self.CONFIG_FILE)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                logger.info(f" Configuration loaded from {self.CONFIG_FILE}")
                logger.debug(f"   API URL: {self.config.get('api_url', 'N/A')}")
                logger.debug(f"   Token Refresh URL: {self.config.get('token_refresh_url', 'N/A')}")
            else:
                logger.warning(f" Config file {self.CONFIG_FILE} not found. Using default values.")
                # Default configuration
                self.config = {
                    "api_url": "https://www.passhub.store/",
                    "token_refresh_url": "http://127.0.0.1:5000/novaseller-token",
                    "auth_token": "",
                    "email": "",
                    "password": "",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0",
                    "timeout": 60,
                    "request_delay": 0.8,
                    "max_retries": 3,
                    "impersonate": "chrome120"
                }
        except json.JSONDecodeError as e:
            logger.error(f" Error parsing config file {self.CONFIG_FILE}: {e}")
            logger.error("   Using default configuration")
            self.config = {
                "api_url": "https://www.passhub.store/",
                "token_refresh_url": "http://127.0.0.1:5000/novaseller-token",
                "auth_token": "",
                "email": "",
                "password": "",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0",
                "timeout": 60,
                "request_delay": 0.8,
                "max_retries": 3,
                "impersonate": "chrome120"
            }
        except Exception as e:
            logger.error(f" Unexpected error loading config file {self.CONFIG_FILE}: {e}")
            raise

    

    def _initialize_session(self):
        """Initialize or reinitialize the session with current configuration"""
        logger.info("🔧 Initializing session...")
        
        self.api_url = self.config.get("api_url", "https://www.passhub.store/")
        self.token_refresh_url = self.config.get("token_refresh_url", "http://127.0.0.1:5000/novaseller-token")
        
        user_agent = self.config.get("user_agent", 
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0")
        
        # Build authorization header if auth_token is available
        auth_header = f"Bearer {self.auth_token}" if self.auth_token else ""
        
        self.default_headers = {
            "User-Agent": user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "X-Source": "panel",
            "Connection": "close",
            "Content-Type": "application/json",
        }
        
        # Add Authorization header only if auth_token is available
        if auth_header:
            self.default_headers["Authorization"] = auth_header
        else:
            logger.warning(" No Authorization header added - auth_token is not available")

        #  SESSION (IMPORTANT)
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)

        # IMPORTANT TLS fingerprinting
        impersonate = self.config.get("impersonate", "chrome120")
        self.session.impersonate = impersonate
        logger.info(f" Session initialized with impersonate: {impersonate}")
        logger.debug(f"   API URL: {self.api_url}")
        logger.debug(f"   Token Refresh URL: {self.token_refresh_url}")
        if self.auth_token:
            logger.debug(f"   Auth token: {self.auth_token[:20]}...")
        else:
            logger.debug("   Auth token: Not set")
    
    def _refresh_token(self):
        """Refresh the access token by calling the VPS endpoint"""
        # Reload config to get latest email/password if they changed
        self._load_config()
        
        # Update email/password from config if not set via parameters
        if not self._email_from_param and self.config.get("email"):
            self.email = self.config.get("email")
        if not self._password_from_param and self.config.get("password"):
            self.password = self.config.get("password")
        
        # Get latest token refresh URL from config
        token_refresh_url = self.config.get("token_refresh_url", "http://127.0.0.1:5000/novaseller-token")
        
        if not self.email or not self.password:
            logger.error(" Email and password are required for token refresh")
            raise ValueError("Email and password are required for token refresh")
        
        logger.info(f" Refreshing token for email: {self.email[:10]}...")
        logger.debug(f"   Token refresh URL: {token_refresh_url}")
        
        try:
            payload = {
                "email": self.email,
                "password": self.password
            }
            
            timeout = self.config.get("timeout", 60)
            logger.debug(f"   Request timeout: {timeout}s")
            
            response = session.post(
                token_refresh_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout
            )
            response.raise_for_status()
            logger.info(f" Token refresh request successful (status: {response.status_code})")
            
            data = response.json()
            logger.debug(f"   Response keys: {list(data.keys())}")
            
            # Extract access_token from response
            # Response structure: {"data": {"access_token": "...", ...}, "respCode": 200, "success": true}
            # Or direct API response structure
            new_token = None
            vps_data = None
            
            # Try nested structure first (Flask wrapped response)
            if "data" in data and isinstance(data["data"], dict):
                vps_data = data["data"]
                new_token = vps_data.get("access_token")
                logger.debug("   Found token in nested 'data' structure")
            # Try direct structure
            elif "access_token" in data:
                vps_data = data
                new_token = data.get("access_token")
                logger.debug("   Found token in direct structure")
            
            if new_token:
                self.auth_token = new_token
                # Update session headers
                self.session.headers.update({
                    "Authorization": f"Bearer {self.auth_token}"
                })
                logger.info(f" Token updated successfully: {self.auth_token[:20]}...")
                
                # Save token and any other relevant data from VPS to config file if it wasn't provided via parameter
                if not hasattr(self, '_auth_token_from_param') or not self._auth_token_from_param:
                    self.config["auth_token"] = new_token
                    
                    # Save any other relevant fields from VPS response if they exist
                    if vps_data:
                        # Check for other fields that might be useful to save
                        # (e.g., refresh_token, expires_in, etc. - but only if they exist in response)
                        fields_to_save = ["refresh_token", "expires_in", "token_type"]
                        for field in fields_to_save:
                            if field in vps_data and field not in ["email", "password"]:  # Don't save credentials
                                self.config[field] = vps_data[field]
                                logger.debug(f"   Saved {field} from VPS response")
                    
                    if self._save_config():
                        logger.info(f" Token and VPS data saved to config file: {self.CONFIG_FILE}")
                    else:
                        logger.warning(f" Failed to save token to config file")
                else:
                    logger.debug("   Token not saved to config (provided via parameter)")
                
                return True
            
            logger.warning(f" Could not extract access_token from response: {data}")
            return False
        except std_requests.exceptions.HTTPError as e:
            logger.error(f" HTTP Error refreshing token: {e}")
            logger.error(f"   Response status: {response.status_code}")
            logger.error(f"   Response body: {response.text[:200]}")
            return False
        except std_requests.exceptions.RequestException as e:
            logger.error(f" Request Error refreshing token: {e}")
            return False
        except Exception as e:
            logger.error(f" Unexpected error refreshing token: {e}")
            return False
    # -----------------------
    # Core Request Handler
    # -----------------------
    def _send_request(self, method: str, endpoint: str, body: dict | None = None, retries: int = None):
        # Reload config to get latest settings
        self._load_config()
        
        # Get dynamic values from config
        api_url = self.config.get("api_url", "https://www.passhub.store/")
        if not api_url.endswith("/"):
            api_url += "/"
        
        url = api_url + endpoint.lstrip("/")
        
        if retries is None:
            retries = self.config.get("max_retries", 3)
        
        request_delay = self.config.get("request_delay", 0.8)
        timeout = self.config.get("timeout", 60)
        
        logger.info(f" Sending {method} request to: {url}")
        logger.debug(f"   Endpoint: {endpoint}")
        logger.debug(f"   Max retries: {retries}")
        logger.debug(f"   Timeout: {timeout}s")
        if body:
            logger.debug(f"   Request body keys: {list(body.keys())}")
        
        token_refreshed = False

        for attempt in range(1, retries + 1):
            try:
                if attempt > 1:
                    logger.info(f" Retry attempt {attempt}/{retries}")
                
                time.sleep(request_delay)  # Cloudflare-friendly delay

                r = self.session.request(
                    method=method,
                    url=url,
                    json=body,
                    timeout=timeout,
                )
                
                logger.info(f" Response received (status: {r.status_code})")
                response_data = r.json()
                logger.debug(f"   Response keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Not a dict'}")
                
                # Check for 401 error with "Invalid access token"
                if (r.status_code == 401 or 
                    (isinstance(response_data, dict) and 
                     response_data.get("respCode") == 401 and 
                     "Invalid access token" in str(response_data.get("respMsg", "")))):
                    
                    logger.warning(f" Invalid access token detected (status: {r.status_code})")
                    
                    # Try to refresh token if not already refreshed
                    if not token_refreshed and self.email and self.password:
                        logger.info(" Attempting to refresh token...")
                        if self._refresh_token():
                            logger.info(" Token refreshed successfully. Retrying request...")
                            token_refreshed = True
                            # Continue to retry the request with new token
                            continue
                        else:
                            logger.error(" Failed to refresh token")
                    else:
                        if not self.email or not self.password:
                            logger.error(" Cannot refresh token: email or password not available")
                    
                    # Return error if token refresh failed or not possible
                    logger.error(f" Request failed due to invalid token")
                    return response_data
                
                logger.info(f" Request successful")
                return response_data

            except requests.exceptions.HTTPError as e:
                logger.error(f" HTTP Error on attempt {attempt}/{retries}: {e}")
                if attempt == retries:
                    return {
                        "success": False,
                        "error": str(e),
                        "attempts": attempt,
                    }
            except requests.exceptions.RequestException as e:
                logger.error(f" Request Error on attempt {attempt}/{retries}: {e}")
                if attempt == retries:
                    return {
                        "success": False,
                        "error": str(e),
                        "attempts": attempt,
                    }
            except Exception as e:
                logger.error(f" Unexpected Error on attempt {attempt}/{retries}: {e}")
                if attempt == retries:
                    return {
                        "success": False,
                        "error": str(e),
                        "attempts": attempt,
                    }


    # -----------------------
    # API Methods
    # -----------------------

    def get_current_user(self):
        """Get current user information"""
        logger.info(" Fetching current user information...")
        result = self._send_request("GET", "api-user/users/current")
        if result and isinstance(result, dict) and result.get("success") is not False:
            logger.info(" Current user information retrieved successfully")
        else:
            logger.warning(f" Failed to get current user: {result}")
        return result
    
    def get_recharge_task_list(self, page=1, limit=10, status=None, account=None):
        """Get recharge task list with optional filters"""
        logger.info(f" Fetching recharge task list (page: {page}, limit: {limit})...")
        
        body = {
            "page": page,
            "limit": limit,
        }

        if status is not None:
            body["status"] = status
            logger.debug(f"   Filtering by status: {status}")
        if account:
            body["account"] = account
            logger.debug(f"   Filtering by account: {account[:10]}...")

        result = self._send_request(
            "POST",
            "api/card/recharge/task/list",
            body=body,
        )
        
        if result and isinstance(result, dict) and result.get("success") is not False:
            logger.info(" Recharge task list retrieved successfully")
            # Log some details if available
            if "data" in result and isinstance(result["data"], dict):
                if "list" in result["data"]:
                    logger.debug(f"   Found {len(result['data']['list'])} tasks")
        else:
            logger.warning(f" Failed to get recharge task list: {result}")
        
        return result
    
    def _fetch_page_thread_safe(self, page: int, limit: int):
        """Thread-safe helper to fetch a single page - creates its own session"""
        try:
            # Reload config to get latest settings
            self._load_config()
            
            # Create a new session for this thread
            thread_session = requests.Session()
            
            # Build headers (same as main session)
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "X-Source": "panel",
                "Connection": "close",
                "Content-Type": "application/json",
            }
            
            # Add Authorization header if auth_token is available
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            
            thread_session.headers.update(headers)
            
            # Apply TLS fingerprinting if configured
            impersonate = self.config.get("impersonate", "chrome120")
            thread_session.impersonate = impersonate
            
            api_url = self.config.get("api_url", "https://www.passhub.store/")
            if not api_url.endswith("/"):
                api_url += "/"
            
            url = api_url + "api/card/recharge/task/list"
            
            body = {
                "page": page,
                "limit": limit,
            }
            
            timeout = self.config.get("timeout", 20)
            
            logger.debug(f"   Thread fetching page {page}...")
            r = thread_session.post(url, json=body, timeout=timeout)
            r.raise_for_status()
            result = r.json()
            
            # Check if API returned an error response
            if result and isinstance(result, dict) and result.get("success") is False:
                logger.warning(f"   Page {page} returned success=False: {result.get('message', 'Unknown error')}")
                return page, None
            
            return page, result
        except Exception as e:
            logger.error(f"   Error fetching page {page}: {e}")
            return page, None
    
    def get_all_accounts_with_remaining_days(self, limit=10, threads=5, delay=0.25):
        """
        Fetch all accounts with remaining days by paginating through all pages using multi-threading
        
        Args:
            limit: Number of items per page
            threads: Number of parallel threads to use for fetching pages
            delay: Delay in seconds between batches
        """
        logger.info(f" Fetching all accounts with remaining days (threads: {threads}, limit: {limit})...")
        
        all_accounts = []
        current_page = 1
        stop_after_page = None
        
        while True:
            # Create batch of pages to fetch in parallel
            batch = list(range(current_page, current_page + threads))
            logger.info(f" Dispatching pages {batch[0]} → {batch[-1]}")
            
            results = []
            
            # Fetch pages in parallel
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._fetch_page_thread_safe, p, limit): p for p in batch}
                for future in as_completed(futures):
                    page_num = futures[future]
                    try:
                        page, data = future.result()
                        if data is None:
                            logger.error(f" Failed to fetch page {page_num}")
                            # Stop on error
                            results = []
                            break
                        results.append((page, data))
                    except Exception as e:
                        logger.error(f" Exception fetching page {page_num}: {e}")
                        results = []
                        break
            
            if not results:
                break
            
            # Sort results by page number
            results.sort(key=lambda x: x[0])
            
            empty_hit = False
            
            # Process each page result
            for page, result in results:
                if not result or not isinstance(result, dict):
                    logger.error(f" Invalid result for page {page}")
                    continue
                
                # Check response structure - could be data.rows or data.list
                data = result.get("data", {})
                rows = data.get("rows", []) or data.get("list", [])
                
                logger.info(f"   Page {page}: Found {len(rows)} rows")
                
                if not rows:
                    logger.warning(f"   Page {page} has no rows → pagination end")
                    empty_hit = True
                    break
                
                # Check if this is the last page
                if data.get("lastPage", False):
                    logger.info(f"   Page {page} has lastPage=True → will stop after this batch")
                    stop_after_page = page
                
                # Extract accounts with remaining days
                for row in rows:
                    # Get account email - prefer 'account' field, fallback to 'email'
                    account_email = row.get("account") or row.get("email")
                    
                    # Get remaining days - field name is 'remainingDay' (string format)
                    remaining_day_str = row.get("remainingDay")
                    
                    if not account_email:
                        logger.warning(f"    Skipping row - no account/email field found: {row.get('taskId', 'unknown')}")
                        continue
                    
                    # Convert remainingDay string to float for comparison
                    remaining_days = 0.0
                    if remaining_day_str is not None:
                        try:
                            remaining_days = float(remaining_day_str)
                        except (ValueError, TypeError):
                            logger.warning(f"    Could not parse remainingDay for {account_email}: {remaining_day_str}")
                            remaining_days = 0.0
                    
                    # Check if account has remaining days > 0
                    if remaining_days > 0:
                        all_accounts.append(account_email)
                        print(f"    Account with remaining days: {account_email} ({remaining_days} days)")
                        logger.info(f"    Account with remaining days: {account_email} ({remaining_days} days)")
                    else:
                        logger.debug(f"Skipping {account_email} (remaining days: {remaining_days})")
            
            if empty_hit:
                break
            
            # Check if we should stop after this batch
            if stop_after_page is not None and current_page + threads - 1 >= stop_after_page:
                break
            
            # Move to next batch
            current_page += threads
            time.sleep(delay)
        
        print(f"\n Total accounts with remaining days found: {len(all_accounts)}")
        logger.info(f" Total accounts with remaining days found: {len(all_accounts)}")
        return all_accounts




# api = FamilyCinemaAPI()
# print(api.get_current_user())
# print(api.get_recharge_task_list())

# Temporary hardcoded emails for testing
emails = [
    "ark.1959mary1@arkodeitv.com",
    "ark.eliyah3@arkodeitv.com",
    "ark.eliyah@arkodeitv.com",
    "ark.elliot@arkodeitv.com",
    "ark.emmacoro2@arkodeitv.com",
    "ark.emmacoro@arkodeitv.com",
    "ark.erick@arkodeitv.com",
    "ark.25natalia@arkodeitv.com",
    "ark.3811moni@arkodeitv.com",
    "ark.504yoda@arkodeitv.com",
    "ark.604brownkan2@arkodeitv.com",
    "ark.604brownkan@arkodeitv.com",
    "ark.65columbia2@arkodeitv.com",
    "ark.65columbia3@arkodeitv.com",
    "ark.65columbia@arkodeitv.com",
    "ark.789happy2@arkodeitv.com",
    "ark.789happy3@arkodeitv.com",
    "ark.789happy@arkodeitv.com",
    "ark.Angelmead@arkodeitv.com",
    "ark.Godisdope2@arkodeitv.com",
    "ark.Dana2@arkodeitv.com",
    "ark.Dana@arkodeitv.com",
    "ark.June@arkodeitv.com",
    "ark.Kenneth2@arkodeitv.com",
    "ark.Smootht87@arkodeitv.com",
    "ark.Spuddy@arkodeitv.com",
    "ark.aber2@arkodeitv.com",
    "ark.aber@arkodeitv.com"
]



def run_continuous_monitoring():
    """Run continuous monitoring with configurable cycle interval - fetches emails dynamically from API"""
    config = get_config()
    cycle_interval_minutes = config.get("violations", {}).get("cycle_interval_minutes", 20)
    cycle_interval = timedelta(minutes=cycle_interval_minutes)
    
    logger.info("="*60)
    logger.info(" Starting Continuous Monitoring System")
    logger.info(f"   Cycle Interval: {cycle_interval_minutes} minutes")
    logger.info("   Emails will be fetched dynamically from API each cycle")
    logger.info("="*60)
    
    cycle_number = 0
    accounts_api = None  # Initialize API instance
    
    while True:
        try:
            cycle_number += 1
            cycle_start_time = datetime.now()
            
            logger.info("")
            logger.info("="*60)
            logger.info(f" CYCLE #{cycle_number} - Starting at {cycle_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("="*60)
            
            # Step 1: Fetch accounts with remaining days from API
            logger.info("")
            logger.info(" Step 1: Fetching accounts with remaining days from API...")
            try:
                if accounts_api is None:
                    accounts_api = FamilyCinemaAPI()
                
                accounts_with_days = accounts_api.get_all_accounts_with_remaining_days(limit=10)
                logger.info(f"   Found {len(accounts_with_days)} accounts with remaining days")
                
                # Use emails as-is (all emails should already start with "ark." prefix)
                api_emails = []
                for email in accounts_with_days:
                    if email.startswith("ark."):
                        api_emails.append(email)
                        logger.debug(f"   Using email: {email}")
                    else:
                        logger.warning(f"   Skipping email without 'ark.' prefix: {email}")
                
                logger.info(f"   Using {len(api_emails)} emails from API")
                
                # Add hardcoded temporary emails for testing
                # logger.info(f"   Adding {len(emails)} hardcoded temporary emails...")
                # for test_email in emails:
                #     if test_email not in api_emails:
                #         api_emails.append(test_email)
                #         logger.debug(f"   Added hardcoded email: {test_email}")
                
                # logger.info(f"   Total emails after adding hardcoded emails: {len(api_emails)}")
               
            except Exception as e:
                logger.error(f"   Error fetching accounts from API: {e}")
                logger.warning("   Will try to use emails from CSV as fallback...")
                # Fallback: use emails from CSV if API fails
                stored_tokens, _ = load_tokens()
                api_emails = list(stored_tokens.keys())
                logger.info(f"   Using {len(api_emails)} emails from CSV as fallback")
                
                # Add hardcoded temporary emails for testing
                logger.info(f"   Adding {len(emails)} hardcoded temporary emails...")
                for test_email in emails:
                    if test_email not in api_emails:
                        api_emails.append(test_email)
                        logger.debug(f"   Added hardcoded email: {test_email}")
                
                logger.info(f"   Total emails after adding hardcoded emails: {len(api_emails)}")
            
            # Step 2: Compare with CSV and find new emails
            logger.info("")
            logger.info(" Step 2: Comparing with CSV to find new emails...")
            stored_tokens, violation_counts = load_tokens()
            existing_emails = set(stored_tokens.keys())
            
            new_emails = []
            for email in api_emails:
                if email not in existing_emails:
                    new_emails.append(email)
            
            if new_emails:
                logger.info(f"   Found {len(new_emails)} new email(s) not in CSV:")
                for email in new_emails:
                    logger.info(f"     - {email}")
                
                # Step 3: Process new emails first (to get tokens and add to CSV)
                logger.info("")
                logger.info(" Step 3: Processing new emails first...")
                process_emails(new_emails)
                
                # Reload tokens after processing new emails
                stored_tokens, violation_counts = load_tokens()
                logger.info(f"   New emails processed and added to CSV")
            else:
                logger.info("   No new emails found - all accounts already in CSV")
            
            # Step 4: Process all emails from API (all accounts with remaining days)
            logger.info("")
            logger.info(f" Step 4: Processing all emails ({len(api_emails)} total)...")
            logger.info(f"   All emails fetched from API: {len(api_emails)} emails")
            
            # Step 5: Process all emails (fetched from API)
            process_emails(api_emails)
            
            cycle_end_time = datetime.now()
            cycle_duration = cycle_end_time - cycle_start_time
            
            logger.info("")
            logger.info("="*60)
            logger.info(f" CYCLE #{cycle_number} - Completed")
            logger.info(f"   Duration: {cycle_duration.total_seconds()/60:.2f} minutes")
            logger.info(f"   Finished at: {cycle_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Calculate next cycle time
            next_cycle_time = cycle_start_time + cycle_interval
            time_until_next = next_cycle_time - cycle_end_time
            
            if time_until_next.total_seconds() > 0:
                wait_seconds = time_until_next.total_seconds()
                logger.info(f" Waiting {wait_seconds/60:.2f} minutes until next cycle...")
                logger.info(f"   Next cycle will start at: {next_cycle_time.strftime('%Y-%m-%d %H:%M:%S')}")
                logger.info("="*60)
                time.sleep(wait_seconds)
            else:
                logger.warning(f" Cycle took longer than interval! Starting next cycle immediately...")
                logger.info("="*60)
                time.sleep(1)  # Small delay to prevent tight loop
                
        except KeyboardInterrupt:
            logger.info("")
            logger.info("="*60)
            logger.info(" Monitoring stopped by user (Ctrl+C)")
            logger.info("="*60)
            break
        except Exception as e:
            logger.error(f" Error in monitoring cycle: {e}")
            logger.error(f"   Continuing to next cycle in 60 seconds...")
            time.sleep(60)  # Wait 1 minute before retrying


if __name__ == "__main__":
    # Start continuous monitoring - emails will be fetched dynamically from API each cycle
    run_continuous_monitoring()
