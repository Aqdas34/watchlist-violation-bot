import winreg
import time
import ctypes
import socket
import subprocess
import psutil
import os
import sys
import json
import logging
from datetime import datetime
import shutil
import random
import pyautogui
from playwright.sync_api import sync_playwright

# === Logging Configuration ===
LOG_FILE = "server_proxy_rotator.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()  # Also log to console
    ]
)
logger = logging.getLogger(__name__)


PROXIES_FILE = "proxies.json"
MAX_FAILED_COUNT = 3  # Proxy will be excluded if failed_count >= 3

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROFILE_PATHS = [
        rf"C:\temp_profile\automation_profile_{n}" for n in range(1, 11)
    ]
EDGE_PROFILE_PATH = None  # Base path to store Edge profiles
# Path to your virtual environment
VENV_PATH = r"C:\Users\Administrator\Desktop\new_code\venv\Scripts\activate.bat"
ROTATE_PROXY_SIGNAL_FILE = "rotate_proxy.flag"  # Signal file to trigger proxy rotation
REQUEST_COUNT_FILE = "request_count.txt"  # File to track request count per proxy
MAX_REQUESTS_PER_PROXY = 8  # Rotate after this many requests
REMOTE_DEBUGGING_PORT = 9223  # Port for remote debugging
CURRENT_PROFILE_FILE = "current_profile.txt"  # File to track current profile path

# === Profile Code Constants and Functions (copied from profile_code.py) ===
EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PROFILE_BASE_PATH = r"C:\temp_profile"

# === ctypes setup for mouse ===
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
user32 = ctypes.windll.user32
SCREEN_WIDTH = user32.GetSystemMetrics(0)
SCREEN_HEIGHT = user32.GetSystemMetrics(1)

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

def open_edge_profile(profile_number: int):
    profile_dir = os.path.join(PROFILE_BASE_PATH, f"automation_profile_{profile_number}")
    EXTENSIONS = [
        r"C:\temp_profile\extensions\extension_one",
        r"C:\temp_profile\extensions\extension_two"
    ]

    extension_arg = f"--load-extension={','.join(EXTENSIONS)}"

    command = [
            EDGE_PATH,
            extension_arg,
            f"--remote-debugging-port=9223", 
            f"--user-data-dir={profile_dir}", 
            "--start-maximized",
        ]

    logger.info(f"🚀 Opening Edge profile {profile_number}...")
    logger.info(f"🚀 Profile path: {profile_dir}")
    subprocess.Popen(command)
    logger.info(f"✅ Edge process started for profile {profile_number}")
    time.sleep(5)

    location = pyautogui.locateCenterOnScreen("pics/sign_without_data.png", confidence=0.8)
    if not location:
        logger.warning("❌ Sign without data not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)
    location = pyautogui.locateCenterOnScreen("pics/confirm_and_continue.png", confidence=0.8)
    if not location:
        logger.warning("❌ Confirm and continue not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)

    location = pyautogui.locateCenterOnScreen("pics/confirm_and_browse.png", confidence=0.8)
    if not location:
        logger.warning("❌ Confirm and browse not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)

def delete_edge_profile(profile_number: int):
    profile_dir = os.path.join(PROFILE_BASE_PATH, f"automation_profile_{profile_number}")

    if not os.path.exists(profile_dir):
        logger.warning(f"❌ Profile does not exist: {profile_dir}")
        return

    try:
        shutil.rmtree(profile_dir)
        logger.info(f"🗑️ Deleted Edge profile {profile_number}")
    except Exception as e:
        logger.error(f"❌ Failed to delete profile {profile_number}: {e}")

def extract_profile_number(profile_path: str) -> int:
    """Extract profile number from profile path like 'C:\\temp_profile\\automation_profile_1'"""
    try:
        # Extract the profile number from the path
        # Path format: C:\temp_profile\automation_profile_{number}
        profile_name = os.path.basename(profile_path)
        if profile_name.startswith("automation_profile_"):
            number_str = profile_name.replace("automation_profile_", "")
            return int(number_str)
        return None
    except Exception as e:
        logger.error(f"❌ Failed to extract profile number from {profile_path}: {e}")
        return None

def recreate_edge_profile(profile_number: int):
    """Delete and recreate an Edge profile"""
    logger.info(f"🔄 Recreating Edge profile {profile_number}...")
    delete_edge_profile(profile_number)
    time.sleep(2)  # Wait a bit before recreating
    open_edge_profile(profile_number)
    visit_and_press_ctrl_2()
    logger.info(f"✅ Successfully recreated Edge profile {profile_number}")

# =====================================================
#  EDGE PATH DETECTION
# =====================================================
def find_edge_path():
    """Find the executable path for Microsoft Edge"""
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    
    for path in edge_paths:
        if os.path.exists(path):
            return path
    
    raise FileNotFoundError("Microsoft Edge not found. Please install Edge or check the path.")

# =====================================================
#  PROFILE MANAGEMENT HELPERS
# =====================================================
def set_current_profile_path(profile_path):
    """Set current profile path to file"""
    try:
        with open(CURRENT_PROFILE_FILE, 'w') as f:
            f.write(profile_path)
        logger.info(f"[PROFILE] Current profile path saved: {profile_path}")
    except Exception as e:
        logger.error(f"[ERROR] Failed to write current profile: {e}")




def visit_and_press_ctrl_2():
    pw = sync_playwright().start()

    try:
        browser = pw.chromium.connect_over_cdp("http://127.0.0.1:9223")
        context = browser.contexts[0]

        # 🔴 Close ONLY the first tab (if it exists)
        if context.pages:
            context.pages[0].close()

        page = context.pages[0]
        # 🟢 Open a new tab
        # page = context.new_page()
        # page.set_default_timeout(60000)

        # page.goto("https://member.watchlist-pro.com/login", timeout=60000)
        page.goto(
    "https://member.watchlist-pro.com/login",
    timeout=60000,
    wait_until="domcontentloaded"
)


        # 🔥 Bring Edge to front so PyAutoGUI works
        page.bring_to_front()
        time.sleep(2)

        # 🔽 Zoom out using OS-level keys
        for _ in range(2):
            pyautogui.hotkey('ctrl', '-')
            time.sleep(0.5)

    except Exception as e:
        print("Error:", e)


# =====================================================
#  OPEN EDGE WITH THE NEW PROXY AND PROFILE
# =====================================================
def open_edge():
    """Open Microsoft Edge with the specified profile and proxy"""
    try:
        edge_path = find_edge_path()
        EXTENSIONS = [
        r"C:\temp_profile\extensions\extension_one",
        r"C:\temp_profile\extensions\extension_two"
    ]

        extension_arg = f"--load-extension={','.join(EXTENSIONS)}"
        subprocess.Popen([edge_path,
        extension_arg, 
                          f"--remote-debugging-port={REMOTE_DEBUGGING_PORT}", 
                          f"--user-data-dir={EDGE_PROFILE_PATH}", 
                          "--start-maximized",
                          ])
        logger.info(f"[OPEN] Edge opened with profile: {EDGE_PROFILE_PATH}")
        # Save current profile path
        set_current_profile_path(EDGE_PROFILE_PATH)
    except FileNotFoundError as e:
        logger.error(f"[ERROR] {e}")
        raise
    except Exception as e:
        logger.error(f"[ERROR] Failed to open Edge: {e}")
        raise

# =====================================================
#  CLOSE EDGE
# =====================================================
def close_edge():
    """Close Edge processes using the specified profile path"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'msedge.exe' in proc.info['name']:
                cmdline = " ".join(proc.info['cmdline'] or [])
                if f'--user-data-dir={EDGE_PROFILE_PATH}' in cmdline:
                    logger.info(f"[CLOSE] Closing Edge process (PID: {proc.info['pid']})...")
                    proc.terminate()
                    proc.wait(timeout=5)  # Wait for process termination
                    logger.info(f"[CLOSE] Edge process (PID: {proc.info['pid']}) terminated.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.TimeoutExpired):
            pass

# =====================================================
#  CHECK AND RESTART THE PYTHON SERVER
# =====================================================

def check_and_restart_server():
    # Kill old server
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'python.exe' in proc.info['name'] and 'app.py' in str(proc.info['cmdline']):
                logger.info(f"[STOP] Found running Python server (PID: {proc.info['pid']}). Terminating...")
                proc.terminate()
                proc.wait()
                logger.info("[STOP] Python server terminated.")
        except:
            pass

    # Correct python from venv
    python_exe = os.path.join(os.path.dirname(VENV_PATH), "python.exe")

    logger.info(f"[START] Starting Python server using → {python_exe}")

    subprocess.Popen([python_exe, "app.py"])
    logger.info("[START] Python server started.")

# =====================================================
#  APPLY PROXY TO WINDOWS
# =====================================================
def apply_refresh():
    INTERNET_OPTION_REFRESH = 37
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)

def set_proxy(proxy):
    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(reg, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(reg, "ProxyServer", 0, winreg.REG_SZ, proxy)
        winreg.CloseKey(reg)

        apply_refresh()
        logger.info(f"[APPLIED] Proxy applied → {proxy}")

    except Exception as e:
        logger.error(f"[ERROR] Failed to set proxy: {e}")

# =====================================================
#  CHECK FOR ROTATION SIGNAL
# =====================================================
def check_rotation_signal():
    """Check if rotation signal file exists"""
    return os.path.exists(ROTATE_PROXY_SIGNAL_FILE)

def clear_rotation_signal():
    """Remove rotation signal file"""
    try:
        if os.path.exists(ROTATE_PROXY_SIGNAL_FILE):
            os.remove(ROTATE_PROXY_SIGNAL_FILE)
            logger.info(f"[SIGNAL] Rotation signal file cleared.")
    except Exception as e:
        logger.error(f"[ERROR] Failed to clear signal file: {e}")

def get_request_count():
    """Get current request count"""
    try:
        if os.path.exists(REQUEST_COUNT_FILE):
            with open(REQUEST_COUNT_FILE, 'r') as f:
                count = int(f.read().strip() or 0)
            return count
        return 0
    except Exception as e:
        logger.error(f"[ERROR] Failed to read request count: {e}")
        return 0

def reset_request_count():
    """Reset request count to 0"""
    try:
        with open(REQUEST_COUNT_FILE, 'w') as f:
            f.write("0")
        logger.info(f"[RESET] Request count reset to 0.")
    except Exception as e:
        logger.error(f"[ERROR] Failed to reset request count: {e}")

# =====================================================
#  PROXY JSON MANAGEMENT
# =====================================================
def load_proxies():
    """Load proxies from JSON file"""
    try:
        if os.path.exists(PROXIES_FILE):
            with open(PROXIES_FILE, 'r') as f:
                proxies = json.load(f)
            return proxies
        else:
            # Create default proxies file if it doesn't exist
            default_proxies = [
                {"proxy": "203.160.121.123:5323", "failed_count": 0},
                {"proxy": "208.72.210.94:7379", "failed_count": 0},
                {"proxy": "45.56.148.132:5786", "failed_count": 0},
                {"proxy": "9.142.206.120:6786", "failed_count": 0},
                {"proxy": "208.72.211.145:6930", "failed_count": 0},
                {"proxy": "66.43.6.113:7984", "failed_count": 0},
                {"proxy": "9.142.213.136:7301", "failed_count": 0},
                {"proxy": "9.142.202.35:6702", "failed_count": 0},
                {"proxy": "138.226.75.192:5382", "failed_count": 0},
                {"proxy": "199.115.178.20:6804", "failed_count": 0}
            ]
            save_proxies(default_proxies)
            return default_proxies
    except Exception as e:
        logger.error(f"[ERROR] Failed to load proxies: {e}")
        return []

def save_proxies(proxies):
    """Save proxies to JSON file"""
    try:
        with open(PROXIES_FILE, 'w') as f:
            json.dump(proxies, f, indent=4)
        logger.info(f"[SAVE] Proxies saved to {PROXIES_FILE}")
    except Exception as e:
        logger.error(f"[ERROR] Failed to save proxies: {e}")

def get_available_proxies(proxies):
    """Get list of proxies with failed_count < MAX_FAILED_COUNT"""
    return [p for p in proxies if p.get("failed_count", 0) < MAX_FAILED_COUNT]

def increment_proxy_failed_count(proxies, proxy_address):
    """Increment failed_count for a specific proxy"""
    for proxy in proxies:
        if proxy["proxy"] == proxy_address:
            proxy["failed_count"] = proxy.get("failed_count", 0) + 1
            logger.warning(f"[FAIL] Proxy {proxy_address} failed_count incremented to {proxy['failed_count']}")
            if proxy["failed_count"] >= MAX_FAILED_COUNT:
                logger.warning(f"[SKIP] Proxy {proxy_address} will be excluded from rotation (failed_count >= {MAX_FAILED_COUNT})")
            save_proxies(proxies)
            return True
    return False

def get_next_proxy_index(proxies, current_index):
    """Get next available proxy index, skipping proxies with failed_count >= MAX_FAILED_COUNT"""
    available_proxies = get_available_proxies(proxies)
    if not available_proxies:
        logger.warning("[WARNING] No available proxies! All proxies have failed_count >= 3")
        return None
    
    # If current_index is -1 (initial selection), start from 0
    if current_index < 0:
        start_index = 0
    else:
        # Find next available proxy starting from current_index + 1
        start_index = (current_index + 1) % len(proxies)
    
    attempts = 0
    
    while attempts < len(proxies):
        proxy = proxies[start_index]
        if proxy.get("failed_count", 0) < MAX_FAILED_COUNT:
            return start_index
        start_index = (start_index + 1) % len(proxies)
        attempts += 1
    
    # If we couldn't find one, return first available
    for i, proxy in enumerate(proxies):
        if proxy.get("failed_count", 0) < MAX_FAILED_COUNT:
            return i
    
    return None



def close_all_edge():
    """Close ALL Edge processes (any profile)."""
    killed = 0
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if (proc.info['name'] or '').lower() == "msedge.exe":
                logger.info(f"[CLOSE-ALL] Terminating Edge PID={proc.info['pid']}")
                proc.terminate()
                killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Wait + force kill if needed
    gone, alive = psutil.wait_procs(
        [p for p in psutil.process_iter(['name']) if (p.info['name'] or '').lower() == "msedge.exe"],
        timeout=5
    )

    # Force kill any still alive
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if (proc.info['name'] or '').lower() == "msedge.exe":
                logger.warning(f"[CLOSE-ALL] Force killing Edge PID={proc.info['pid']}")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    logger.info(f"[CLOSE-ALL] Done. Attempted to close Edge instances: {killed}")



# =====================================================
#  ROTATION LOOP (ONLY ROTATE ON SIGNAL - errCode -3040)
# =====================================================
def rotate_proxies():
    global EDGE_PROFILE_PATH
    
    # Verify Edge is available
    try:
        find_edge_path()
        logger.info(f"[INIT] Using Microsoft Edge")
    except FileNotFoundError as e:
        logger.error(f"[ERROR] {e}")
        return
    
    close_all_edge()
    time.sleep(3)

    proxies = load_proxies()
    if not proxies:
        logger.error("[ERROR] No proxies loaded. Exiting.")
        return
    
    # Get first available proxy
    current_proxy_index = get_next_proxy_index(proxies, -1)
    if current_proxy_index is None:
        logger.error("[ERROR] No available proxies. All proxies have failed_count >= 3")
        return
    
    profile_index_counter = 0
    proxy_info = proxies[current_proxy_index]
    proxy = proxy_info["proxy"]
    profile_index = profile_index_counter % len(PROFILE_PATHS)
    EDGE_PROFILE_PATH = PROFILE_PATHS[profile_index]
    
    logger.info(f"[INIT] Starting with proxy: {proxy} (index: {current_proxy_index})")
    set_proxy(proxy)
    open_edge()  # Open Edge with the profile and proxy
    reset_request_count()  # Reset request count for new proxy
    time.sleep(3)
    check_and_restart_server()
    signal_check_interval = 1  # seconds - check every 1 seconds for rotation signal
    recreated_after_robot_error = False  # True after 1st robot error + recreate; 2nd error -> increment proxy failed_count
    
    while True:
        if check_rotation_signal():
            clear_rotation_signal()
            logger.info(f"\n[ROTATE] Rotation triggered by robot error code -3040.")
            
            current_profile_number = extract_profile_number(EDGE_PROFILE_PATH) if EDGE_PROFILE_PATH else None
            current_proxy_address = proxies[current_proxy_index]["proxy"]
            
            if recreated_after_robot_error:
                # Second error on same proxy after recreate -> increment proxy failed_count and rotate
                logger.info(f"[ROBOT ERROR] Same error on recreated profile -> incrementing failed_count for proxy {current_proxy_address}")
                increment_proxy_failed_count(proxies, current_proxy_address)
                proxies = load_proxies()
                close_edge()
                recreated_after_robot_error = False
                
                next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                if next_proxy_index is None:
                    logger.error("[ERROR] No available proxies left. All proxies have failed_count >= 3")
                    logger.info("[INFO] Waiting for manual intervention or proxy reset...")
                    time.sleep(10)
                    proxies = load_proxies()
                    next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                    if next_proxy_index is None:
                        continue
                current_proxy_index = next_proxy_index
                profile_index_counter += 1
                profile_index = profile_index_counter % len(PROFILE_PATHS)
                EDGE_PROFILE_PATH = PROFILE_PATHS[profile_index]
                
                proxy_info = proxies[current_proxy_index]
                proxy = proxy_info["proxy"]
                logger.info(f"[ROTATE] Switched to proxy: {proxy} (index: {current_proxy_index}, failed_count: {proxy_info.get('failed_count', 0)})")
                set_proxy(proxy)
                reset_request_count()
                logger.info(f"[PROFILE] Profile Name = {EDGE_PROFILE_PATH}")
                time.sleep(3)
                open_edge()
                time.sleep(3)
            else:
                # First robot error -> close, delete, recreate, close, open via open_edge, same proxy. Do NOT increment.
                if not current_profile_number:
                    logger.warning("[ROBOT ERROR] No profile to recreate -> incrementing proxy and rotating.")
                    increment_proxy_failed_count(proxies, current_proxy_address)
                    proxies = load_proxies()
                    close_edge()
                    next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                    if next_proxy_index is None:
                        time.sleep(10)
                        proxies = load_proxies()
                        next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                        if next_proxy_index is None:
                            continue
                    current_proxy_index = next_proxy_index
                    profile_index_counter += 1
                    profile_index = profile_index_counter % len(PROFILE_PATHS)
                    EDGE_PROFILE_PATH = PROFILE_PATHS[profile_index]
                    proxy_info = proxies[current_proxy_index]
                    proxy = proxy_info["proxy"]
                    set_proxy(proxy)
                    reset_request_count()
                    time.sleep(3)
                    open_edge()
                    time.sleep(3)
                else:
                    logger.info(f"[ROBOT ERROR] First error -> recreating profile {current_profile_number}, keeping proxy {current_proxy_address}")
                    close_edge()
                    time.sleep(2)
                    
                    try:
                        delete_edge_profile(current_profile_number)
                        time.sleep(2)
                        profile_dir = os.path.join(r"C:\temp_profile", f"automation_profile_{current_profile_number}")
                        EDGE_PROFILE_PATH = profile_dir
                        logger.info(f"[PROFILE RECREATION] Opening new Edge profile {current_profile_number}...")
                        open_edge_profile(current_profile_number)
                        logger.info(f"[PROFILE RECREATION] Configuring profile {current_profile_number}...")
                        visit_and_press_ctrl_2()
                        time.sleep(5)
                        set_current_profile_path(EDGE_PROFILE_PATH)
                        logger.info(f"[PROFILE RECREATION] Closing and reopening via open_edge (same proxy)...")
                        close_edge()
                        time.sleep(2)
                        set_proxy(current_proxy_address)
                        time.sleep(1)
                        open_edge()
                        time.sleep(3)
                        recreated_after_robot_error = True
                        logger.info(f"[PROFILE RECREATION] Done. Same proxy {current_proxy_address}. If error recurs -> failed_count incremented.")
                    except Exception as e:
                        logger.error(f"[PROFILE RECREATION] Failed: {e}. Rotating to next proxy.")
                        increment_proxy_failed_count(proxies, current_proxy_address)
                        proxies = load_proxies()
                        close_edge()
                        next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                        if next_proxy_index is None:
                            time.sleep(10)
                            proxies = load_proxies()
                            next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                            if next_proxy_index is None:
                                continue
                        current_proxy_index = next_proxy_index
                        profile_index_counter += 1
                        profile_index = profile_index_counter % len(PROFILE_PATHS)
                        EDGE_PROFILE_PATH = PROFILE_PATHS[profile_index]
                        proxy_info = proxies[current_proxy_index]
                        proxy = proxy_info["proxy"]
                        set_proxy(proxy)
                        reset_request_count()
                        time.sleep(3)
                        open_edge()
                        time.sleep(3)
            
            check_and_restart_server()
        
        request_count = get_request_count()

        if request_count >= MAX_REQUESTS_PER_PROXY:
            logger.info("Edge profile changed")
            close_edge()
            recreated_after_robot_error = False
            
            # Reload proxies to get latest failed_count
            proxies = load_proxies()
            
            # Get next available proxy
            next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
            if next_proxy_index is None:
                logger.error("[ERROR] No available proxies left. All proxies have failed_count >= 3")
                logger.info("[INFO] Waiting for manual intervention or proxy reset...")
                time.sleep(10)  # Wait before checking again
                proxies = load_proxies()  # Reload in case proxies were reset
                next_proxy_index = get_next_proxy_index(proxies, current_proxy_index)
                if next_proxy_index is None:
                    continue
            
            current_proxy_index = next_proxy_index
            reset_request_count()
            rotation_reason = f"Request count reached {request_count}/{MAX_REQUESTS_PER_PROXY}"
            profile_index_counter += 1 
            profile_index = profile_index_counter % len(PROFILE_PATHS)
            EDGE_PROFILE_PATH = PROFILE_PATHS[profile_index]
            
            logger.info(f"Profile Name = {EDGE_PROFILE_PATH}")
            proxy_info = proxies[current_proxy_index]
            proxy = proxy_info["proxy"]
            logger.info(f"[ROTATE] Switched to proxy: {proxy} (index: {current_proxy_index}, failed_count: {proxy_info.get('failed_count', 0)})")
            set_proxy(proxy)
            time.sleep(3)
            open_edge()
            time.sleep(3)
            check_and_restart_server()

        time.sleep(signal_check_interval)  # Check for signal every 1 seconds

# =====================================================
#  MAIN
# =====================================================
if __name__ == "__main__":
    logger.info("Starting Windows System Proxy Rotator…")
    rotate_proxies()

