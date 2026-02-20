from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from queue import Queue, PriorityQueue
import threading
import time
import random
import pyautogui
import ctypes
import os
import logging
import json
import requests
from datetime import datetime
import psutil
import subprocess
import shutil
# Optional: CapSolver for solving reCAPTCHA v2
try:
    import capsolver  # pip install capsolver
except Exception:
    capsolver = None
# Configure requests session defaults for better reliability
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# Disable SSL warnings and configure connection pooling
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# === Logging Configuration ===
from logging.handlers import RotatingFileHandler

LOG_FILE = "app.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'),
        logging.StreamHandler()  # Also log to console
    ]
)
logger = logging.getLogger(__name__)


def _get_capsolver_api_key() -> str | None:
    """
    Get CapSolver API key from env or local config file.
    Priority:
      1) CAPSOLVER_API_KEY environment variable
      2) sharing_config.json -> api -> capsolver_api_key
    """
    # Check sharing_config.json first (centralized config)
    try:
        config_file = "sharing_config.json"
        if os.path.exists(config_file):
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            key = config.get("api", {}).get("capsolver_api_key")
            if key:
                return str(key).strip()
    except Exception as e:
        logger.warning(f"CapSolver key read failed from sharing_config.json: {repr(e)}")

  
    # Hardcoded fallback
    key = "CAP-A740D7F826D24024186093D971BBE6584CC659459256BB72481EC35B35657F52"
    if key:
        return key.strip()

    return None


def solve_recaptcha_v2_if_present(page, *, max_wait_seconds: int = 120, max_attempts: int = 3) -> bool:
    """
    Detect and solve reCAPTCHA v2 (visible checkbox/challenge) using CapSolver.
    If captcha isn't present, returns False.
    If solved/injected, returns True.
    """
    try:
        # Quick detection: iframe src contains recaptcha OR any data-sitekey on the page
        has_iframe = page.locator('iframe[src*=\"recaptcha\"]').count() > 0
        has_sitekey = page.locator('[data-sitekey]').count() > 0
        if not (has_iframe or has_sitekey):
            return False

        logger.info("CAPTCHA detected. Preparing CapSolver task...")

        api_key = _get_capsolver_api_key()
        if not api_key:
            logger.error("CAPSOLVER_API_KEY not set (or missing capsolver_api_key in family_cinema_config.json).")
            return False

        # IMPORTANT: call CapSolver API using a proxy-disabled requests session.
        # Many servers have an authenticated system proxy configured which breaks calls (407).
        def _capsolver_post(endpoint: str, payload: dict, *, timeout: int = 60) -> dict | None:
            session = requests.Session()
            session.trust_env = False  # ignore HTTP(S)_PROXY env vars / system proxy
            adapter = HTTPAdapter(
                pool_connections=1,
                pool_maxsize=1,
                max_retries=Retry(
                    total=2,
                    backoff_factor=1,
                    status_forcelist=[500, 502, 503, 504],
                    allowed_methods=["POST"],
                ),
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            try:
                r = session.post(endpoint, json=payload, timeout=timeout)
                return r.json()
            except Exception as e:
                logger.error(f"CapSolver HTTP request failed: {repr(e)}", exc_info=True)
                return None
            finally:
                session.close()

        # Extract sitekey (+ detect invisible) once per detection
        website_key = None
        is_invisible = False
        try:
            first = page.locator('[data-sitekey]').first
            website_key = first.get_attribute("data-sitekey")
            size_attr = (first.get_attribute("data-size") or "").strip().lower()
            if size_attr == "invisible":
                is_invisible = True
        except Exception:
            website_key = None

        if not website_key:
            # Fallback: try to regex from HTML
            html = page.content()
            m = re.search(r'data-sitekey\\s*=\\s*[\"\\\']([^\"\\\']+)[\"\\\']', html)
            if m:
                website_key = m.group(1)

        if not website_key:
            logger.error("CAPTCHA detected but could not find reCAPTCHA sitekey on the page.")
            return False

        website_url = page.url
        try:
            user_agent = page.evaluate("() => navigator.userAgent") or ""
        except Exception:
            user_agent = ""

        logger.info(f"reCAPTCHA flags: isInvisible={is_invisible}, userAgent_present={bool(user_agent)}")

        # Retry the whole CapSolver task flow if solve fails (e.g. ERROR_CAPTCHA_SOLVE_FAILED)
        retryable_error_codes = {"ERROR_CAPTCHA_SOLVE_FAILED"}
        attempts = max(1, int(max_attempts))

        token = None
        for attempt in range(1, attempts + 1):
            logger.info(f"CapSolver attempt {attempt}/{attempts} - creating task...")

            create_payload = {
                "clientKey": api_key,
                "task": {
                    "type": "ReCaptchaV2TaskProxyLess",
                    "websiteURL": website_url,
                    "websiteKey": website_key,
                    "isInvisible": bool(is_invisible),
                    "userAgent": user_agent,
                },
            }

            create_resp = _capsolver_post("https://api.capsolver.com/createTask", create_payload, timeout=60)
            if not create_resp:
                logger.warning("CapSolver createTask returned no response.")
                if attempt < attempts:
                    time.sleep(2)
                    continue
                return False

            if create_resp.get("errorId") != 0:
                err_code = create_resp.get("errorCode")
                err_desc = create_resp.get("errorDescription")
                logger.error(f"CapSolver createTask failed: errorCode={err_code}, errorDescription={err_desc}")
                if attempt < attempts and err_code in retryable_error_codes:
                    time.sleep(2)
                    continue
                return False

            task_id = create_resp.get("taskId")
            if not task_id:
                logger.error(f"CapSolver createTask returned no taskId. Raw response: {create_resp}")
                if attempt < attempts:
                    time.sleep(2)
                    continue
                return False

            logger.info(f"CapSolver task created (taskId={task_id}). Waiting for result...")

            start = time.time()
            while time.time() - start < max_wait_seconds:
                time.sleep(2)
                result_payload = {"clientKey": api_key, "taskId": task_id}
                result_resp = _capsolver_post("https://api.capsolver.com/getTaskResult", result_payload, timeout=60)
                if not result_resp:
                    continue

                if result_resp.get("errorId") not in (None, 0):
                    err_code = result_resp.get("errorCode")
                    err_desc = result_resp.get("errorDescription")
                    logger.error(f"CapSolver getTaskResult failed: errorCode={err_code}, errorDescription={err_desc}")
                    if attempt < attempts and err_code in retryable_error_codes:
                        logger.info("CapSolver solve failed; retrying from scratch...")
                        break  # break polling loop -> next attempt
                    return False

                status = result_resp.get("status")
                if status == "ready":
                    solution = result_resp.get("solution") or {}
                    token = solution.get("gRecaptchaResponse")
                    break
                if status in ("processing", None):
                    continue

                logger.error(f"CapSolver returned unexpected status={status}. Raw response: {result_resp}")
                if attempt < attempts:
                    logger.info("Unexpected status; retrying from scratch...")
                    break
                return False

            if token:
                break

            if attempt < attempts:
                time.sleep(2)

        if not token:
            logger.error("CapSolver failed to solve CAPTCHA after retries.")
            return False

        logger.info("CapSolver token received. Injecting token into page...")

        page.evaluate(
            """
            (token) => {
              const candidates = [
                document.getElementById('g-recaptcha-response'),
                document.querySelector('textarea[name="g-recaptcha-response"]'),
                document.querySelector('textarea#g-recaptcha-response')
              ].filter(Boolean);

              if (candidates.length === 0) {
                // Create textarea if site expects it
                const ta = document.createElement('textarea');
                ta.id = 'g-recaptcha-response';
                ta.name = 'g-recaptcha-response';
                ta.style.display = 'none';
                document.body.appendChild(ta);
                candidates.push(ta);
              }

              for (const el of candidates) {
                el.value = token;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
              }

              // Some sites read this value from JS
              window.__gRecaptchaResponse = token;

              // If the widget has an explicit callback, call it
              const cbAttrEl = document.querySelector('[data-sitekey][data-callback]');
              if (cbAttrEl) {
                const cbName = cbAttrEl.getAttribute('data-callback');
                if (cbName && typeof window[cbName] === 'function') {
                  try { window[cbName](token); } catch (e) {}
                }
              }

              // Try to trigger callbacks from grecaptcha client config (common for invisible recaptcha)
              try {
                const cfg = window.___grecaptcha_cfg;
                const clients = cfg && cfg.clients ? cfg.clients : null;
                if (clients) {
                  const visit = (obj) => {
                    if (!obj || typeof obj !== 'object') return;
                    for (const k of Object.keys(obj)) {
                      const v = obj[k];
                      if (typeof v === 'function') continue;
                      if (v && typeof v === 'object') visit(v);
                      if (k === 'callback' && typeof v === 'function') {
                        try { v(token); } catch (e) {}
                      }
                    }
                  };
                  visit(clients);
                }
              } catch (e) {}
            }
            """,
            token,
        )

        logger.info("CAPTCHA token injected + callbacks triggered.")
        return True
    except Exception as e:
        logger.error(f"CAPTCHA solve/inject failed: {repr(e)}", exc_info=True)
        return False


def extract_token_from_localstorage(page) -> dict | None:
    """
    Best-effort fallback: scan localStorage for access token fields.
    Returns a dict shaped like the token API response (at least {"success": True, "data": {...}}) or None.
    """
    try:
        # Use the same proven snippet as sessions_copy.py
        storage = page.evaluate(
            """
            () => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            }
            """
        )
        if not isinstance(storage, dict) or not storage:
            return None

        # Log storage keys (safe) for debugging
        try:
            keys = sorted([str(k) for k in storage.keys()])
            logger.info(f"LocalStorage items found: {len(keys)}")
            logger.info(f"LocalStorage keys: {keys[:50]}{' ...' if len(keys) > 50 else ''}")
            admin_token_preview = (
                storage.get("Admin-Token")
                or storage.get("admin-token")
                or storage.get("Admin_token")
                or storage.get("admin_token")
            )
            if isinstance(admin_token_preview, str) and admin_token_preview.strip():
                preview = admin_token_preview.strip()
                logger.info(f"LocalStorage Admin_token preview: {preview[:20]}...")
        except Exception:
            # never fail token extraction because of logging
            pass

        # direct common keys first (including your known key)
        for k in (
            "Admin-Token",
            "admin-token",
            "Admin_token",
            "admin_token",
            "access_token",
            "accessToken",
            "token",
            "auth_token",
            "authToken",
        ):
            v = storage.get(k)
            if isinstance(v, str) and v.strip():
                return {"success": True, "data": {"access_token": v.strip()}}

        # try JSON values that may contain access_token
        for k, v in storage.items():
            if not isinstance(v, str) or not v.strip():
                continue
            try:
                parsed = json.loads(v)
            except Exception:
                parsed = None

            if isinstance(parsed, dict):
                at = parsed.get("access_token") or parsed.get("accessToken") or parsed.get("token")
                if isinstance(at, str) and at.strip():
                    return {"success": True, "data": {"access_token": at.strip()}}

        # heuristic JWT-like value
        for k, v in storage.items():
            if isinstance(v, str) and "eyJ" in v and len(v) > 100:
                return {"success": True, "data": {"access_token": v.strip()}}

        return None
    except Exception as e:
        logger.warning(f"LocalStorage token fallback failed: {repr(e)}", exc_info=True)
        return None


def save_token_to_callback_and_config(access_token, refresh_token=None, expires_in=None, token_type=None):
    """Save access_token to MyFamilyCinema callback (DB) and family_cinema_config.json."""
    try:
        logger.info(f"Saving token to database via: {CALLBACK_AUTH_URL}")
        response = http_post(
            CALLBACK_AUTH_URL,
            json_body={"token": access_token},
            timeout=60,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                logger.info(f"  Token saved to database successfully: {result.get('message')}")
            else:
                logger.error(f"  Failed to save token: {result.get('error')}")
        else:
            logger.error(f"  Failed to save token: HTTP {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"  Error saving token to database: {str(e)}")

    try:
        logger.info(f"Updating token in {FAMILY_CINEMA_CONFIG_FILE}")
        if os.path.exists(FAMILY_CINEMA_CONFIG_FILE):
            with open(FAMILY_CINEMA_CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
        else:
            config = {}
        config["auth_token"] = access_token
        if refresh_token:
            config["refresh_token"] = refresh_token
        if expires_in:
            config["expires_in"] = expires_in
        if token_type:
            config["token_type"] = token_type
        with open(FAMILY_CINEMA_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        logger.info(f"  Token updated in {FAMILY_CINEMA_CONFIG_FILE} successfully")
    except Exception as e:
        logger.error(f"  Error updating token in config file: {str(e)}")


def create_session_with_retries():
    """Create a requests session with retry strategy and proxy disabled"""
    session = requests.Session()

    # IMPORTANT: ignore proxy env vars / system proxy
    session.trust_env = False

    adapter = HTTPAdapter(
        pool_connections=1,
        pool_maxsize=1,
        max_retries=Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST", "GET"]
        )
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def http_get(url: str, *, timeout: int = 60, headers: dict | None = None):
    """GET helper that uses proxy-disabled session."""
    session = create_session_with_retries()
    try:
        return session.get(url, timeout=timeout, headers=headers)
    finally:
        session.close()


def http_post(url: str, *, json_body: dict | None = None, timeout: int = 60, headers: dict | None = None):
    """POST helper that uses proxy-disabled session."""
    session = create_session_with_retries()
    try:
        return session.post(url, json=json_body, timeout=timeout, headers=headers)
    finally:
        session.close()
app = Flask(__name__)



#"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --user-data-dir="C:\temp_profile\automation_profile_4" --new-window



# === Globals ===
TASK_QUEUE = PriorityQueue()
# Priority levels: 0 = highest priority (novaseller-token), 1 = normal priority (other requests)
PLAYWRIGHT_CONTEXT = None
PAGE = None
ROTATE_PROXY_SIGNAL_FILE = "rotate_proxy.flag"  # Signal file to trigger proxy rotation
REQUEST_COUNT_FILE = "request_count.txt"  # File to track request count per proxy
MAX_REQUESTS_PER_PROXY = 1  # Rotate after this many requests

# Timeouts (ms). Profile recreation + open can be slow; use higher values.
DEFAULT_TIMEOUT_MS = 90000   # 90s for goto, click, expect_response
PAGE_DEFAULT_TIMEOUT_MS = 90000  # Playwright page default

# Token capture: don't wait too long; if dashboard loads, use localStorage fallback.
TOKEN_LISTENER_WAIT_SECONDS = 20

# Welcome/dashboard URL: if we land here after goto(login), another request may have already logged in.
WELCOME_URL_PART = "passhub.store/welcome"
CALLBACK_AUTH_URL = "https://pay.arkodeitv.com/billing/modules/addons/myfamilycinema/callback.php?endpoint=authToken"
FAMILY_CINEMA_CONFIG_FILE = "family_cinema_config.json"


# === ctypes setup for mouse ===
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
user32 = ctypes.windll.user32
SCREEN_WIDTH = user32.GetSystemMetrics(0)
SCREEN_HEIGHT = user32.GetSystemMetrics(1)


def handle_password_dialog():
    # Wait for the dialog to appear (this depends on your internet speed and form submission timing)
    time.sleep(3)

    try:
    # Look for the "Not now" button (use the screenshot of "Not now" for image recognition)
        location = pyautogui.locateCenterOnScreen('pics/not_now_button.png', confidence=0.8)
        if location:
            print("  'Not now' button found.")
            logger.info(f"  'Not now' button found at {location}")
            pyautogui.click(location)
        else:
            logger.info("  'Not now' button not found.")
    except Exception as e:
        pass
    time.sleep(1)



# === Proxy rotation signal helper ===
def signal_proxy_rotation():
    """Create a flag file that tells rotation_proxy.py to rotate the proxy."""
    logger.info("  errCode -3040 detected. Signaling proxy rotation immediately...")
    try:
        with open(ROTATE_PROXY_SIGNAL_FILE, 'w') as f:
            f.write("rotate")
        logger.info(f"  Signal file created: {ROTATE_PROXY_SIGNAL_FILE}")
    except Exception as e:
        logger.error(f"  Failed to create signal file: {e}")



REMOTE_DEBUGGING_PORT = 9223  # already in your other script

def get_pid_listening_on_port(port: int):
    """Return PID that is LISTENING on 127.0.0.1:<port> (or any addr), else None."""
    for c in psutil.net_connections(kind="tcp"):
        if not c.laddr:
            continue
        if c.laddr.port == port and c.status == psutil.CONN_LISTEN:
            return c.pid
    return None


def kill_edge_except_pid(keep_pid: int, only_debug_port: int | None = None):
    """
    Kill all msedge.exe except keep_pid.
    If only_debug_port is provided, kill only Edge processes that include that port in cmdline.
    """
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["pid"] == keep_pid:
                continue

            name = (proc.info["name"] or "").lower()
            if name != "msedge.exe":
                continue

            if only_debug_port is not None:
                cmd = " ".join(proc.info["cmdline"] or [])
                if f"--remote-debugging-port={only_debug_port}" not in cmd:
                    # skip edges not related to this automation port
                    continue

            logger.warning(f"[EDGE-CLEANUP] Closing extra Edge PID={proc.info['pid']}")
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # optional: force kill if some stayed alive
    time.sleep(2)
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name == "msedge.exe" and proc.info["pid"] != keep_pid:
                if only_debug_port is not None:
                    cmd = " ".join(proc.info["cmdline"] or [])
                    if f"--remote-debugging-port={only_debug_port}" not in cmd:
                        continue
                logger.warning(f"[EDGE-CLEANUP] Force killing Edge PID={proc.info['pid']}")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def ensure_single_edge_on_port(port: int):
    """
    Ensure only one Edge instance remains for the given debugging port.
    Keeps the one that is actually listening on that port.
    """
    keep_pid = get_pid_listening_on_port(port)
    if not keep_pid:
        logger.warning(f"[EDGE-CLEANUP] No process is listening on port {port}")
        return None

    logger.info(f"[EDGE-CLEANUP] Edge/CDP listener on port {port} is PID={keep_pid}")
    # Safer: kill only Edge processes started with same debugging port
    kill_edge_except_pid(keep_pid, only_debug_port=port)
    return keep_pid



# === Worker thread ===
def browser_worker():
    global PLAYWRIGHT_CONTEXT, PAGE
    pw = sync_playwright().start()
    connected = False
    max_retries = 10
    
    for attempt in range(max_retries):
        try:
            # ensure_single_edge_on_port(REMOTE_DEBUGGING_PORT)
            PLAYWRIGHT_CONTEXT = pw.chromium.connect_over_cdp("http://127.0.0.1:9223")
            context = PLAYWRIGHT_CONTEXT.contexts[0]

            if len(context.pages) > 1:
                context.pages[1].close()
            PAGE = context.pages[0]
            PAGE.set_default_timeout(PAGE_DEFAULT_TIMEOUT_MS)
            
            logger.info(f"  Connected to Chrome via CDP (timeout={PAGE_DEFAULT_TIMEOUT_MS}ms)")
            connected = True
            break
        except Exception as e:
            logger.warning(f"  Could not connect to Chrome (Attempt {attempt+1}/{max_retries}): {e}")
            time.sleep(3)
            
    if not connected:
        logger.error("  Failed to connect to Chrome after all retries. Exiting worker.")
        return




    while True:
        task_item = TASK_QUEUE.get()
        if task_item is None:
            break
        # PriorityQueue returns (priority, task_tuple)
        priority, task = task_item
        func, args, result_queue, retries = (*task, 0) if len(task) == 3 else task
        
        # Log priority processing
        if priority == 0:
            logger.info(f"🔥 Processing HIGH PRIORITY task: {func.__name__}")
        else:
            logger.debug(f"📋 Processing normal priority task: {func.__name__}")
        
        try:
            result = func(*args, result_queue=result_queue, retries=retries)
            if result is not None:
                result_queue.put(result)
        except Exception as e:
            # No more automatic retries – just return the error once
            logger.error(f"  Exception in {func.__name__}: {e}")
            result_queue.put({
                "status": "error",
                "message": str(e),
                "errCode": None
            })
        finally:
            TASK_QUEUE.task_done()


# === Request Counter Helpers ===
def get_request_count():
    """Get current request count without incrementing"""
    try:
        if os.path.exists(REQUEST_COUNT_FILE):
            with open(REQUEST_COUNT_FILE, 'r') as f:
                count = int(f.read().strip() or 0)
            return count
        return 0
    except Exception as e:
        logger.error(f"  Failed to read request count: {e}")
        return 0

def increment_request_count():
    """Increment request count and return new count"""
    try:
        if os.path.exists(REQUEST_COUNT_FILE):
            with open(REQUEST_COUNT_FILE, 'r') as f:
                count = int(f.read().strip() or 0)
        else:
            count = 0
        count += 1
        with open(REQUEST_COUNT_FILE, 'w') as f:
            f.write(str(count))
        return count
    except Exception as e:
        logger.error(f"  Failed to increment request count: {e}")
        return 0

# === Helpers ===
def clear_input_field(selector):
    PAGE.click(selector, timeout=DEFAULT_TIMEOUT_MS)
    PAGE.keyboard.press("Control+A")
    PAGE.keyboard.press("Backspace")
    time.sleep(random.uniform(0.1, 0.3))




def click_at(x, y, steps=20):
    """Smooth mouse movement and click"""
    start_x = random.randint(0, SCREEN_WIDTH - 1)
    start_y = random.randint(0, SCREEN_HEIGHT - 1)

    for i in range(steps + 1):
        new_x = int(start_x + (x - start_x) * i / steps)
        new_y = int(start_y + (y - start_y) * i / steps)
        abs_x = int(new_x * 65535 / SCREEN_WIDTH)
        abs_y = int(new_y * 65535 / SCREEN_HEIGHT)
        ctypes.windll.user32.mouse_event(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, abs_x, abs_y, 0, 0)
        time.sleep(random.uniform(0.01, 0.03))
    time.sleep(1)
    ctypes.windll.user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(random.uniform(0.05, 0.1))
    ctypes.windll.user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)


def human_type(page, selector, text):
    for char in text:
        page.type(selector, char)
        time.sleep(random.uniform(0.05, 0.15))

def human_type_password(page, selector, text):
    for char in text:
        page.type(selector, char)
        # time.sleep(random.uniform(0.05, 0.15))

# === Actions ===
def send_otp_action(email, result_queue, retries=3):

    
    global PAGE  # Removed CURRENT_PAGE_TYPE
    
    try:
        # Always go to the register page, removing CURRENT_PAGE_TYPE check
        PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
        # Removed CURRENT_PAGE_TYPE = "register"
        
        clear_input_field('input[placeholder="Email"]')

        human_type(PAGE, 'input[placeholder="Email"]', email)
        time.sleep(2)

        theme_font_color = PAGE.evaluate(
            "() => getComputedStyle(document.body).getPropertyValue('--themeFontColor').trim()"
        )
        logger.info(f"🎨 Theme color: {theme_font_color}")

        if theme_font_color.lower() in ['#fff', '#ffffff']:
            location = pyautogui.locateCenterOnScreen("white_send_button.png", confidence=0.7)
        else:
            location = pyautogui.locateCenterOnScreen("black_send_button.png", confidence=0.8)

        if not location:
            raise Exception("Send OTP button not found")

        click_at(location.x, location.y)

        response_url_part = "user/sendVerificationCode/v1"
        with PAGE.expect_response(lambda r: response_url_part in r.url, timeout=DEFAULT_TIMEOUT_MS) as resp_info:
            pass
        resp = resp_info.value
        data = resp.json()

        logger.info(f"Send OTP response: {data}")

        if data.get("errCode") == -3040:
            logger.warning(f"[!] errCode -3040 for {email}")
            # Signal rotation - test.py will handle profile recreation and proxy failed_count increment
            signal_proxy_rotation()
            return data
        
        if data.get("errCode") == 0 and data.get('successful'): 
            try:
                PAGE.click(".el-dialog__headerbtn", timeout=DEFAULT_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                logger.warning("  Timeout clicking dialog close button (non-critical)")
                # Non-critical, continue anyway

        return data

    except PlaywrightTimeoutError as e:
        logger.error(f"  send_otp_action timeout: {e}")
        
        # Refresh page for next request
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
            PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {refresh_error}")
        
        # Return timeout error
        return {
            "status": "error",
            "message": f"Timeout: {str(e)}",
            "errCode": None
        }
    except Exception as e:
        logger.error(f"  send_otp_action failed: {e}")
        
        # Refresh page for next request on any error
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
            PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {refresh_error}")
        
        return {
            "status": "error",
            "message": str(e),
            "errCode": None
        }


def register_action(email, otp, password, result_queue, retries=3):
    global PAGE  # Removed CURRENT_PAGE_TYPE
    
    try:
        # Always go to the register page, removing CURRENT_PAGE_TYPE check
        PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
        # Removed CURRENT_PAGE_TYPE = "register"
        
        clear_input_field('input[placeholder="Email"]')
        clear_input_field('input[placeholder="Verification code"]')
        clear_input_field('input[placeholder="New password (at least 6 characters)"]')

        human_type(PAGE, 'input[placeholder="Email"]', email)
        human_type(PAGE, 'input[placeholder="Verification code"]', otp)
        human_type(PAGE, 'input[placeholder="New password (at least 6 characters)"]', password)

        theme_font_color = PAGE.evaluate(
            "() => getComputedStyle(document.body).getPropertyValue('--themeFontColor').trim()"
        )
        logger.info(f"🎨 Theme color: {theme_font_color}")
        if theme_font_color.lower() in ['#fff', '#ffffff']:
            location = pyautogui.locateCenterOnScreen("white_register_button.png", confidence=0.7)
        else:
            location = pyautogui.locateCenterOnScreen("black_register_button.png", confidence=0.7)

        if not location:
            raise Exception("Register button not found")

        click_at(location.x, location.y)
        handle_password_dialog()
        

        response_url_part = "user/signup/v1"
        with PAGE.expect_response(lambda r: response_url_part in r.url, timeout=DEFAULT_TIMEOUT_MS) as resp_info:
            pass
        resp = resp_info.value
        data = resp.json()

        logger.info(f"Register response: {data}")

        if data.get("errCode") == -3040:
            # Signal rotation - test.py will handle profile recreation and proxy failed_count increment
            signal_proxy_rotation()
            return data
        time.sleep(3)
        try:
            PAGE.click(".menu-logout", timeout=DEFAULT_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            logger.warning("  Timeout clicking logout button (non-critical)")
            # Non-critical, continue anyway
        return data

    except PlaywrightTimeoutError as e:
        logger.error(f"  register_action timeout: {e}")
        
        # Refresh page for next request
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
            PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {refresh_error}")
        
        return {
            "status": "error",
            "message": f"Timeout: {str(e)}",
            "errCode": None
        }
    except Exception as e:
        logger.error(f"  register_action failed: {e}")
        
        # Refresh page for next request on any error
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
            PAGE.goto("https://member.watchlist-pro.com/register", timeout=DEFAULT_TIMEOUT_MS)
            
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {refresh_error}")
        
        return {
            "status": "error",
            "message": str(e),
            "errCode": None
        }


def login_action(email, password, result_queue, retries=1):


    global PAGE  # Removed CURRENT_PAGE_TYPE
    
    try:
        # Always go to the login page, removing CURRENT_PAGE_TYPE check
        PAGE.goto("https://member.watchlist-pro.com/login", timeout=DEFAULT_TIMEOUT_MS)
        # Removed CURRENT_PAGE_TYPE = "login"
        
        clear_input_field('input[placeholder="Email"]')
        clear_input_field('input[placeholder="Password"]')

        human_type(PAGE, 'input[placeholder="Email"]', email)
        human_type(PAGE, 'input[placeholder="Password"]', password)

        theme_font_color = PAGE.evaluate(
            "() => getComputedStyle(document.body).getPropertyValue('--themeFontColor').trim()"
        )
        logger.info(f"🎨 Theme color: {theme_font_color}")

        location = None

        
        button_file = "login_button.png"
        if not os.path.exists(button_file):
            logger.warning(f"  {button_file} not found, will try zoom adjustments")
            # Try to locate login button with fallback zoom adjustments
        try:
            location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
        except pyautogui.ImageNotFoundException:
            logger.warning(f"  Could not locate {button_file}, trying zoom out...")
            # Zoom out 2 times (Ctrl -)
            for _ in range(2):
                pyautogui.hotkey('ctrl', '-')
                time.sleep(0.5)
            time.sleep(1)
            try:
                location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
                logger.info("  Found login button after zoom out")
            except pyautogui.ImageNotFoundException:
                logger.warning("  Still not found after zoom out, trying zoom in...")
                # Zoom in 2 times (Ctrl +)
                for _ in range(2):
                    pyautogui.hotkey('ctrl', '+')
                    time.sleep(0.5)
                time.sleep(1)
                try:
                    location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
                    logger.info("  Found login button after zoom in")
                except pyautogui.ImageNotFoundException:
                    logger.error("  Could not locate login button after all zoom adjustments")
                    raise Exception("Login button not found")

        if not location:
            raise Exception("Login button not found")

        # Retry logic for login button click and response wait
        response_url_part = "user/login/v1"
        data = None
        
        for attempt in range(3):
            try:
                logger.info(f"  Attempt {attempt+1}/3: Clicking login button and waiting for response...")
                
                # Wait for response (timeout 30s) while clicking
                # Using 30000ms explicit timeout as requested
                with PAGE.expect_response(lambda r: response_url_part in r.url, timeout=30000) as resp_info:
                    click_at(location.x, location.y)
                    time.sleep(1)
                    handle_password_dialog()
                
                # If we get here, response was successful
                resp = resp_info.value
                data = resp.json()
                logger.info("  Login response received successfully.")
                break # Exit loop heavily relying on break for success flow
                
            except Exception as e:
                logger.warning(f"  Response not received within 30s (Attempt {attempt+1}): {e}")
                if attempt == 2:
                    logger.error("  Max retries reached. Login response failed.")
                    raise e
                logger.info("  Retrying click in 2 seconds...")
                time.sleep(2)

        logger.info(f"Login response: {data}")

        if data.get("errCode") == -3040:
            # Signal rotation - test.py will handle profile recreation and proxy failed_count increment
            signal_proxy_rotation()
            return data

        # Check if login was successful before trying to click logout
        if not data.get("successful") or data.get("errCode") != 0:
            # Login failed - return early without trying to click logout
            logger.warning(f"Login failed: errCode={data.get('errCode')}, message={data.get('message', 'Unknown error')}")
            return data

        # Only click logout if login was successful
        PAGE.click(".menu-logout", timeout=DEFAULT_TIMEOUT_MS)
        return data

    except Exception as e:
        logger.error(f"  login_action failed: {e}")
        
        return {
            "status": "error",
            "message": str(e),
            "errCode": None
        }


# === Flask routes ===
@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.json
    email = data.get("email")
    logger.info(f"Send OTP request received: email={email}")
    if not email:
        logger.warning("Send OTP request missing email")
        return jsonify({"error": "Email required"}), 400
    result_queue = Queue()
    # Priority 1 = normal priority
    TASK_QUEUE.put((1, (send_otp_action, (email,), result_queue, 0)))
    # Process request first, then increment count after completion
    result = result_queue.get()
    count = increment_request_count()
    logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
    return jsonify(result)


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email, otp, password = data.get("email"), data.get("otp"), data.get("password")
    logger.info(f"Register request received: email={email}")
    if not all([email, otp, password]):
        logger.warning("Register request missing email, OTP, or password")
        return jsonify({"error": "Email, OTP, and password required"}), 400
    result_queue = Queue()
    # Priority 1 = normal priority
    TASK_QUEUE.put((1, (register_action, (email, otp, password), result_queue, 0)))
    # Process request first, then increment count after completion
    result = result_queue.get()
    count = increment_request_count()
    logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
    return jsonify(result)



def wlp_login_action(email, password, result_queue, retries=3):
    global PAGE  # Removed CURRENT_PAGE_TYPE
    try:
        # Removed CURRENT_PAGE_TYPE = None
        PAGE.goto("https://cloud.watchlist-pro.com/", timeout=DEFAULT_TIMEOUT_MS)


        # Check if logout button exists and handle logout with confirmation
        time.sleep(2)
        pyautogui.moveTo(210, 360)
        pyautogui.click()

        logout_button_selector = "a.logout_title"
        if PAGE.is_visible(logout_button_selector):
            logger.info("🚪 Logout button found, logging out first...")
            
            # Click the logout button
            PAGE.click(logout_button_selector)
            
            # Wait a bit for the popup to appear
            PAGE.wait_for_timeout(500)
            
            # Check for and click OK button in confirmation dialog
            ok_button_selector = "button.ant-btn.ant-btn-primary span"
            ok_buttons = PAGE.query_selector_all(ok_button_selector)
            for button_span in ok_buttons:
                if button_span.text_content().strip() == "OK":
                    logger.info("✔ OK button found, confirming logout...")
                    button_span.click()
                    break
            
            # Wait a moment and then redirect
            PAGE.wait_for_timeout(1000)
            PAGE.goto("https://cloud.watchlist-pro.com/", timeout=DEFAULT_TIMEOUT_MS)
        else:
            logger.info("Logout button not found")
        
        # Wait for potential logout to complete
        PAGE.wait_for_timeout(3000)
        
        

        # # Clear and fill login fields
        clear_input_field('input[placeholder="Email"]')
        clear_input_field('input[placeholder="Password"]')
        
        human_type(PAGE, 'input[placeholder="Email"]', email)
        # human_type_password(PAGE, 'input[placeholder="Password"]', password)
        PAGE.fill('input[placeholder="Password"]',password)
        
        time.sleep(2)
        pyautogui.moveTo(210, 360)
        pyautogui.click()
        handle_password_dialog()
        
        # Wait for and capture the specific network response
        response_url_part = "https://partner.uiimxdlz.com/cloudpkg/mfc/loginv2"
        with PAGE.expect_response(lambda r: response_url_part in r.url, timeout=DEFAULT_TIMEOUT_MS) as resp_info:
            pass
        resp = resp_info.value
        response_data = resp.json()

        logger.info(f"WLP login response: {response_data}")
        if "result" in response_data and "token" in response_data["result"]:
            logger.info(f"Token: {response_data['result']['token']}")
        
        return {
            "status": "success",
            "data": response_data,
            "message": "WLP login completed successfully"
        }
        
    except Exception as e:
        logger.error(f"  wlp_login_action failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "errCode": None
        }



@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email, password = data.get("email"), data.get("password")
    logger.info(f"Login request received: email={email}")
    if not all([email, password]):
        logger.warning("Login request missing email or password")
        return jsonify({"error": "Email and password required"}), 400
    
    logger.info(f"Login attempt for email={email}")
    result_queue = Queue()
    # Priority 1 = normal priority
    TASK_QUEUE.put((1, (login_action, (email, password), result_queue, 0)))
    
    # Process request first, then increment count after completion
    result = result_queue.get()
    
    # Check if login was successful
    count = increment_request_count()
    logger.info(f"  Login completed (Status: {result.get('successful', 'Unknown') if result else 'None'})")
    logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
    return jsonify(result)

@app.route("/wlp/token-refresh",methods=["POST"])
def wlp_login():
    data = request.json
    email, password = data.get("email"), data.get("password")
    logger.info(f"WLP login request received: email={email}")
    if not all([email, password]):
        logger.warning("WLP login request missing email or password")
        return jsonify({"error": "Email and password required"}), 400
    
    result_queue = Queue()
    # Priority 1 = normal priority
    TASK_QUEUE.put((1, (wlp_login_action, (email, password), result_queue, 0)))
    # Process request first, then increment count after completion
    result = result_queue.get()
    count = increment_request_count()
    logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200




def novaseller_action(email, password, result_queue, retries=3):
    time.sleep(2)
    try:
        extension_off_dialog = pyautogui.locateCenterOnScreen("pics/turn_off_extension.png",confidence=0.8)
        if extension_off_dialog:
            logger.info("Found extension dialog box")
            pyautogui.press('tab')
            time.sleep(0.1)  # small delay between key presses
            # Press Down Arrow
            pyautogui.press('down')
            time.sleep(0.1)
            # Press Enter
            pyautogui.press('enter')
        else:
            logger.info("Extension dialog box not found")

    except Exception as e:
        logger.error(f"Error Extension dialog box: {e}")
    global PAGE  # Removed CURRENT_PAGE_TYPE
    
    try:
        logger.info("Starting novaseller_action...")
        # try:
        #     turn_off_pop_up =  pyautogui.locateCenterOnScreen("pics/turn_off.png", confidence=0.7)
        #     if turn_off_pop_up:

        #         pyautogui.press('tab')
        #         time.sleep(0.5)
        #         pyautogui.press('down')
        #         time.sleep(0.5)
        #         pyautogui.press('enter')
        #         time.sleep(0.5)
        # except Exception as e:
        #     logger.error(f"not there, not clicking turn off pop up button: {e}")

        # Removed CURRENT_PAGE_TYPE = None
        PAGE.goto("https://www.passhub.store/account/login", timeout=DEFAULT_TIMEOUT_MS)
        time.sleep(3)

        # If URL is already welcome/dashboard, another request may have just logged in; use localStorage only.
        try:

            logger.info("Checking if dashboard is already present (welcome URL)...")
            PAGE.wait_for_url("**/welcome**", timeout=10000)
            PAGE.wait_for_load_state("networkidle")
            current_url = (PAGE.url or "").strip()
            logger.info(f"Current URL: {current_url}")
            if WELCOME_URL_PART in current_url or "welcome" in current_url:
                logger.info("Dashboard already present (welcome URL). Fetching from localStorage and updating DB/config.")
                localStorage_data = PAGE.evaluate("""
                    () => {
                        const items = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            items[key] = localStorage.getItem(key);
                        }
                        return items;
                    }
                """)
                access_token = (
                    (localStorage_data or {}).get("Admin-Token")
                    or (localStorage_data or {}).get("admin-token")
                    or (localStorage_data or {}).get("Admin_token")
                    or (localStorage_data or {}).get("admin_token")
                )
                if access_token and isinstance(access_token, str) and access_token.strip():
                    save_token_to_callback_and_config(access_token.strip())
                    if localStorage_data:
                        with open("localstorage.json", "w", encoding="utf-8") as f:
                            json.dump(localStorage_data, f, indent=2)
                        logger.info("LocalStorage saved to localstorage.json")
                    logger.info("Token and storage updated from existing dashboard.")
                    return {"access_token": access_token.strip()}
                logger.warning("Welcome URL but no Admin-Token in localStorage; continuing with login flow.")
        except Exception as e:
            logger.warning(f"Early-exit welcome check failed: {repr(e)}; continuing with login flow.")

        pyautogui.press('enter')
        time.sleep(1)
        logger.info("Navigated to login form")
        # try:
        #     confirm_button = pyautogui.locateCenterOnScreen("pics/confirm_button.png", confidence=0.7)
        #     if confirm_button:
        #         click_at(confirm_button.x, confirm_button.y)
        #     else:
        #         logger.error("Confirm button not found")
        # except Exception as e:
        #     logger.error(f"not there, not clicking confirm button: {e}")

            # raise Exception("Confirm button not found")
        # Click Email tab
        logger.info("Navigating to login form (Email tab)...")

        
        # PAGE.get_by_text("Email", exact=True).click()

        try:
                # 1️⃣ Click Email tab using JS (inside browser)
            PAGE.evaluate("""
                const tabs = document.querySelectorAll('.cus_tabs .tab-item');
                if (tabs.length > 1) {
                    tabs[1].click();
                }
            """)
            time.sleep(1)  # allow UI to update
            email_button = pyautogui.locateCenterOnScreen("pics/email_button.png", confidence=0.7)
            if not email_button:
                logger.error("Email button not found",)
            else:
                click_at(email_button.x, email_button.y)
        except Exception as e:
            logger.error("not there, not clicking email button:",exc_info=True)
            logger.error(f"not there, not clicking email button: {e}")
            # raise Exception("Email button not found")
        logger.info("Clicked Email tab")
        time.sleep(1)
        # # Clear and fill login fields
        logger.info("Clearing Email input...")
        clear_input_field('input[placeholder="Email"]')
        logger.info("Clearing Password input...")
        clear_input_field('input[placeholder="Password"]')
        
        logger.info("Typing email...")
        human_type(PAGE, 'input[placeholder="Email"]', email)
        # human_type_password(PAGE, 'input[placeholder="Password"]', password)
        logger.info("Filling password...")
        PAGE.fill('input[placeholder="Password"]',password)
        time.sleep(1)
        logger.info("Locating login button on screen...")
        location = pyautogui.locateCenterOnScreen("novaseller_login_button.png", confidence=0.7)
        if not location:
            logger.error("Login button not found on screen")
            raise Exception("Login button not found")

        # Start listening for the token response BEFORE clicking login,
        # because the dashboard can load quickly and the response may be missed otherwise.
        response_url_part = "https://www.passhub.store/api-auth/oauth/user/token"
        token_event = threading.Event()
        token_capture: dict[str, object] = {"resp": None, "json": None, "status": None, "url": None}

        def _on_token_response(r):
            try:
                if response_url_part in (r.url or ""):
                    token_capture["resp"] = r
                    token_capture["status"] = r.status
                    token_capture["url"] = r.url
                    try:
                        token_capture["json"] = r.json()
                    except Exception:
                        token_capture["json"] = None
                    token_event.set()
            except Exception:
                # never break the response pipeline
                pass

        PAGE.on("response", _on_token_response)

        logger.info("Clicking login button...")
        click_at(location.x, location.y)
        time.sleep(1)
        handle_password_dialog()

        # If captcha appears after login click, solve it and re-submit
        try:
            logger.info("Checking for CAPTCHA after login click...")
            solved = solve_recaptcha_v2_if_present(PAGE)
            if solved:
                logger.info("CAPTCHA solved. Clicking login button again to submit...")
                # click_at(location.x, location.y)
                
        except Exception as e:
            logger.error(f"CAPTCHA handling error (continuing): {repr(e)}", exc_info=True)
        logger.info("Handling password dialog (if any)...")
        handle_password_dialog()
        
        # Wait for and capture the token API response (robust: listener can't miss early responses)
        logger.info(f"Waiting for token API response (listener, {TOKEN_LISTENER_WAIT_SECONDS}s)...")
        token_event.wait(timeout=max(5, int(TOKEN_LISTENER_WAIT_SECONDS)))

        # Always detach listener
        try:
            PAGE.off("response", _on_token_response)
        except Exception:
            pass

        api_response = token_capture.get("json")
        if not isinstance(api_response, dict):
            # If dashboard is already visible but we missed/failed to parse the token response,
            # try extracting from localStorage as a fallback.
            logger.warning(
                "Token API response not captured/parsed. "
                f"page_url={getattr(PAGE, 'url', None)} token_status={token_capture.get('status')} token_url={token_capture.get('url')}"
            )
            fallback = extract_token_from_localstorage(PAGE)
            if fallback:
                logger.info("Recovered access token from localStorage fallback.")
                api_response = fallback
            else:
                raise Exception("Token API response not captured and no token found in localStorage.")

        if token_capture.get("status") is not None and token_capture.get("url") is not None:
            logger.info(f"Token response captured: {token_capture.get('status')} {token_capture.get('url')}")

        logger.info(f"Novaseller login response: {api_response}")

        if api_response.get("errCode") == -3040:
            logger.warning("Proxy rotation requested (errCode=-3040). Signaling rotation.")
            # Signal rotation - test.py will handle profile recreation and proxy failed_count increment
            signal_proxy_rotation()
            return api_response
        
        # Extract access_token from the response
        logger.info("Extracting tokens from API response...")
        access_token = None
        refresh_token = None
        expires_in = None
        token_type = None
        
        if api_response.get("success") and api_response.get("data") and api_response["data"].get("access_token"):
            access_token = api_response["data"]["access_token"]
            refresh_token = api_response["data"].get("refresh_token")
            expires_in = api_response["data"].get("expires_in")
            token_type = api_response["data"].get("token_type")
            
            logger.info(f"Extracted access_token: {access_token[:20]}...")
            logger.info(
                "Extracted token metadata: "
                f"token_type={token_type}, expires_in={expires_in}, refresh_token_present={bool(refresh_token)}"
            )
            
            save_token_to_callback_and_config(access_token, refresh_token, expires_in, token_type)
        else:
            logger.warning("  No access_token found in API response")
        
        # Wait for page to fully load before accessing localStorage
        PAGE.wait_for_load_state("networkidle")
        time.sleep(2)  # Additional wait to ensure localStorage is populated

        # Get localStorage data
        localStorage_data = PAGE.evaluate("""
            () => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            }
        """)

        logger.info(f"LocalStorage data: {localStorage_data}")

        # Save localStorage to file if not empty
        if localStorage_data:
            with open("localstorage.json", "w", encoding="utf-8") as f:
                json.dump(localStorage_data, f, indent=2)
            logger.info("LocalStorage saved to localstorage.json")
        else:
            logger.warning("LocalStorage is empty, file not created")

        # Return only access_token when API returns data successfully
        if api_response.get("success") and api_response.get("data") and api_response["data"].get("access_token"):
            return {"access_token": api_response["data"]["access_token"]}
        else:
            # Return the full response if no access_token found
            return api_response

    except PlaywrightTimeoutError as e:
        # Note: some exceptions have empty str(e); include repr + full traceback
        logger.error(f"  novaseller_action timeout: {repr(e)}", exc_info=True)
        
        # Refresh page for next request
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {repr(refresh_error)}", exc_info=True)
        
        return {
            "status": "error",
            "message": f"Timeout: {str(e)}",
            "errCode": None
        }
    except Exception as e:
        # Note: some exceptions have empty str(e); include repr + full traceback
        logger.error(f"  novaseller_action failed: {repr(e)}", exc_info=True)
        
        # Refresh page for next request on any error
        try:
            logger.info("  Refreshing page for next request...")
            PAGE.reload(timeout=DEFAULT_TIMEOUT_MS)
            time.sleep(2)
        except Exception as refresh_error:
            logger.error(f"  Failed to refresh page: {repr(refresh_error)}", exc_info=True)
        
        return {
            "status": "error",
            "message": str(e),
            "errCode": None
        }
@app.route("/novaseller-token", methods=["POST"])
def novaseller_token():
    # data = request.json or {}
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    
    # If email/password not provided in request, fetch from config file
    if not email or not password:
        try:
            config_file = "family_cinema_config.json"
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                if not email:
                    email = config.get("email")
                if not password:
                    password = config.get("password")
                logger.info(f"  Using credentials from config file: email={email}")
            else:
                logger.warning(f"Config file not found: {config_file}")
        except Exception as e:
            logger.error(f"  Error reading config file: {str(e)}")
    
    logger.info(f"  Novaseller token request received (HIGH PRIORITY): email={email}")
    if not all([email, password]):
        logger.warning("Novaseller token request missing email or password")
        return jsonify({"error": "Email and password required (provide in request or config file)"}), 400
    result_queue = Queue()
    # Priority 0 = highest priority (processed first)
    TASK_QUEUE.put((0, (novaseller_action, (email, password), result_queue, 0)))
    logger.info(f"  Novaseller token request added to queue with HIGH PRIORITY")
    # Process request first, then increment count after completion
    result = result_queue.get()
    count = increment_request_count()
    logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
    return jsonify(result)

@app.route("/novaseller-token-desktop", methods=["GET", "POST"])
def novaseller_token_desktop():
    """
    Desktop route that:
    1. Fetches token from callback
    2. Tests token by calling api-user/users/current
    3. If token works, returns localStorage
    4. If token doesn't work, calls novaseller-token to refresh
    5. Returns localStorage after refresh
    
    Email and password are read from family_cinema_config.json
    """
    logger.info("  Novaseller token desktop request received")
    
    # Read email and password from family_cinema_config.json
    try:
        config_file = "family_cinema_config.json"
        if not os.path.exists(config_file):
            logger.error(f"  Config file not found: {config_file}")
            return jsonify({"error": "Config file not found"}), 500
        
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        email = config.get("email")
        password = config.get("password")
        
        if not all([email, password]):
            logger.error("  Email or password missing from config file")
            return jsonify({"error": "Email or password missing from config file"}), 500
        
        logger.info(f"  Credentials loaded from config: email={email}")
        
    except Exception as e:
        logger.error(f"  Error reading config file: {str(e)}")
        return jsonify({"error": f"Error reading config file: {str(e)}"}), 500
    
    # Try to get callback_base_url from sharing_config.json, strict fallback
    callback_base_url = "https://pay.arkodeitv.com/billing/modules/addons/myfamilycinema/callback.php"
    try:
        if os.path.exists("sharing_config.json"):
             with open("sharing_config.json", "r", encoding="utf-8") as f:
                shared_conf = json.load(f)
                callback_base_url = shared_conf.get("api", {}).get("callback_url", callback_base_url)
    except Exception as e:
        logger.warning(f"Failed to read callback_url from sharing_config.json: {e}")
    
    # Construct full callback URL
    callback_url = f"{callback_base_url}?endpoint=authToken"

    # callback_url = "https://pay.arkodeitv.com/billing/modules/addons/myfamilycinema/callback.php?endpoint=authToken"
    api_base_url = "https://www.passhub.store/"
    
    # Step 1: Fetch token from callback
    try:
        logger.info("  Fetching token from callback...")
        response = http_get(callback_url, timeout=60)
        
        if response.status_code != 200:
            logger.warning(f"  Failed to fetch token from callback: HTTP {response.status_code}")
            token = None
        else:
            result = response.json()
            if result.get("success") and result.get("token"):
                token = result["token"]
                logger.info(f"  Token fetched from callback: {token[:20]}...")
            else:
                logger.warning("  No token found in callback response")
                token = None
    except Exception as e:
        logger.error(f"  Error fetching token from callback: {str(e)}")
        token = None
    
    # Step 2: Test token if we have one
    token_valid = False
    if token:
        try:
            logger.info("🔍 Testing token validity...")
            test_url = f"{api_base_url}api-user/users/current"
            headers = {
                "Authorization": f"Bearer {token}",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            test_response = http_get(test_url, headers=headers, timeout=60)
            
            # If we get HTTP 200, the token is valid (server accepted it)
            # Rate limits or other API errors don't mean the token is invalid
            if test_response.status_code == 200:
                test_result = test_response.json()
                token_valid = True
                if test_result.get("success") or test_result.get("data"):
                    logger.info("  Token is valid and working")
                else:
                    # Token is valid but might have rate limit or other API-level issues
                    logger.info(f"  Token is valid (HTTP 200) - API response: {test_result.get('message', 'OK')}")
            elif test_response.status_code == 401:
                # Unauthorized - token is invalid or expired
                logger.warning("  Token test failed: Unauthorized (401) - Token is invalid")
                token_valid = False
            else:
                # Other HTTP errors - treat as invalid for safety
                logger.warning(f"  Token test failed: HTTP {test_response.status_code}")
                token_valid = False
        except Exception as e:
            logger.error(f"  Error testing token: {str(e)}")
    
    # Step 3: If token is valid, return localStorage
    if token_valid:
        try:
            logger.info("  Reading localStorage from file...")
            if os.path.exists("localstorage.json"):
                with open("localstorage.json", "r", encoding="utf-8") as f:
                    localStorage_data = json.load(f)
                
                if localStorage_data:
                    logger.info("  Returning localStorage data (token was valid)")
                    return jsonify({
                        "success": True,
                        "token_valid": True,
                        "localStorage": localStorage_data,
                        "message": "Token is valid, returning existing localStorage"
                    })
                else:
                    logger.warning("  localStorage.json is empty")
            else:
                logger.warning("  localStorage.json file not found")
        except Exception as e:
            logger.error(f"  Error reading localStorage: {str(e)}")
    
    # Step 4: Token is invalid or missing, call novaseller-token to refresh
    logger.info("  Token invalid or missing, calling novaseller-token to refresh...")
    try:
        # Call the internal novaseller-token endpoint
        result_queue = Queue()
        TASK_QUEUE.put((0, (novaseller_action, (email, password), result_queue, 0)))
        logger.info("  Refresh request added to queue with HIGH PRIORITY")
        result = result_queue.get()
        count = increment_request_count()
        logger.info(f"  Request count: {count}/{MAX_REQUESTS_PER_PROXY}")
        
        # Check if refresh was successful
        if result.get("success") or (result.get("data") and result.get("data").get("access_token")):
            logger.info("  Token refreshed successfully")
        else:
            logger.error(f"  Token refresh failed: {result}")
            return jsonify({
                "success": False,
                "error": "Failed to refresh token",
                "details": result
            }), 500
        
    except Exception as e:
        logger.error(f"  Error refreshing token: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Error refreshing token: {str(e)}"
        }), 500
    
    # Step 5: Wait for localStorage to be updated, then return it (with retry)
    logger.info("   Waiting for localStorage to be saved...")
    localStorage_data = None
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        time.sleep(retry_delay)
        try:
            if os.path.exists("localstorage.json"):
                with open("localstorage.json", "r", encoding="utf-8") as f:
                    localStorage_data = json.load(f)
                
                if localStorage_data:
                    logger.info(f"  localStorage found after {attempt + 1} attempt(s)")
                    break
                else:
                    logger.warning(f"  localStorage.json is empty (attempt {attempt + 1}/{max_retries})")
            else:
                logger.warning(f"  localStorage.json not found yet (attempt {attempt + 1}/{max_retries})")
        except Exception as e:
            logger.warning(f"  Error reading localStorage (attempt {attempt + 1}/{max_retries}): {str(e)}")
    
    if localStorage_data:
        logger.info("  Returning localStorage data after refresh")
        return jsonify({
            "success": True,
            "token_valid": False,
            "token_refreshed": True,
            "localStorage": localStorage_data,
            "message": "Token refreshed, returning updated localStorage"
        })
    else:
        logger.error("  Failed to read localStorage after refresh")
        return jsonify({
            "success": False,
            "error": "localStorage not available after refresh",
            "message": "Token was refreshed but localStorage could not be retrieved"
        }), 500

# === Start worker thread ===
worker_thread = threading.Thread(target=browser_worker, daemon=True)
worker_thread.start()

if __name__ == "__main__":
    logger.info("Starting Flask application on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000,debug=False, threaded=True)
    