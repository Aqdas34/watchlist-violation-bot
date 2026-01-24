import subprocess
import os
import shutil
import time
import random
import pyautogui
import ctypes
from playwright.sync_api import sync_playwright
import psutil


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


EDGE_PROFILE_PATH = None



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

    subprocess.Popen(command)
    print(f"✅ Opened Edge profile {profile_number}")
    time.sleep(3)

    location = pyautogui.locateCenterOnScreen("pics/sign_without_data.png", confidence=0.8)
    if not location:
        print("❌ Sign without data not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)
    location = pyautogui.locateCenterOnScreen("pics/confirm_and_continue.png", confidence=0.8)
    if not location:
        print("❌ Confirm and continue not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)


    location = pyautogui.locateCenterOnScreen("pics/confirm_and_browse.png", confidence=0.8)
    if not location:
        print("❌ Confirm and browse not found")
        return
    click_at(location.x, location.y)
    time.sleep(1)

  
    

def delete_edge_profile(profile_number: int):
    profile_dir = os.path.join(PROFILE_BASE_PATH, f"automation_profile_{profile_number}")

    if not os.path.exists(profile_dir):
        print(f"❌ Profile does not exist: {profile_dir}")
        return

    try:
        shutil.rmtree(profile_dir)
        print(f"🗑️ Deleted Edge profile {profile_number}")
    except Exception as e:
        print(f"❌ Failed to delete profile {profile_number}: {e}")


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
        print(f"❌ Failed to extract profile number from {profile_path}: {e}")
        return None


def recreate_edge_profile(profile_number: int):
    """Delete and recreate an Edge profile"""
    print(f"🔄 Recreating Edge profile {profile_number}...")
    delete_edge_profile(profile_number)
    time.sleep(2)  # Wait a bit before recreating
    open_edge_profile(profile_number)
    print(f"✅ Successfully recreated Edge profile {profile_number}")

def close_edge():
    global EDGE_PROFILE_PATH
    """Close Edge processes using the specified profile path"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'msedge.exe' in proc.info['name']:
                cmdline = " ".join(proc.info['cmdline'] or [])
                if f'--user-data-dir={EDGE_PROFILE_PATH}' in cmdline:
                    # logger.info(f"[CLOSE] Closing Edge process (PID: {proc.info['pid']})...")
                    proc.terminate()
                    proc.wait(timeout=5)  # Wait for process termination
                    # logger.info(f"[CLOSE] Edge process (PID: {proc.info['pid']}) terminated.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.TimeoutExpired):
            pass

# Remove the test code at the bottom

# for i in range(1,10):
#     delete_edge_profile(i)
#     open_edge_profile(i)
    # EDGE_PROFILE_PATH = f"C:\\temp_profile\\automation_profile_{i}"
#     print(EDGE_PROFILE_PATH)
#     visit_and_press_ctrl_2()
#     close_edge()
    

i = 1
delete_edge_profile(i)
open_edge_profile(i)
EDGE_PROFILE_PATH = f"C:\\temp_profile\\automation_profile_{i}"
visit_and_press_ctrl_2()
close_edge()




"""

        button_file = "login_button.png"
        if not os.path.exists(button_file):
            logger.warning(f"⚠️ {button_file} not found, will try zoom adjustments")

        # Try to locate login button with fallback zoom adjustments
        location = None
        try:
            location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
        except pyautogui.ImageNotFoundException:
            logger.warning(f"⚠️ Could not locate {button_file}, trying zoom out...")
            # Zoom out 2 times (Ctrl -)
            for _ in range(2):
                pyautogui.hotkey('ctrl', '-')
                time.sleep(0.5)
            time.sleep(1)
            try:
                location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
                logger.info("✅ Found login button after zoom out")
            except pyautogui.ImageNotFoundException:
                logger.warning("⚠️ Still not found after zoom out, trying zoom in...")
                # Zoom in 2 times (Ctrl +)
                for _ in range(2):
                    pyautogui.hotkey('ctrl', '+')
                    time.sleep(0.5)
                time.sleep(1)
                try:
                    location = pyautogui.locateCenterOnScreen(button_file, confidence=0.7)
                    logger.info("✅ Found login button after zoom in")
                except pyautogui.ImageNotFoundException:
                    logger.error("❌ Could not locate login button after all zoom adjustments")
                    raise Exception("Login button not found")

"""