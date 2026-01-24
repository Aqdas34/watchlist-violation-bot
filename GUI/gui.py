import sys
import os
import platform
import requests
import re
from typing import Optional, List, Dict, Any
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea,
    QFrame, QMessageBox, QProgressDialog, QCheckBox,
    QSizePolicy, QGridLayout, QSplitter
)
from PySide6.QtGui import QFont, QIcon, QScreen
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QPropertyAnimation, QEasingCurve, QSize

# API_URL = "http://127.0.0.1:5001/config"
API_URL = "http://51.81.210.236:5001/config"
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")

# Platform detection for cross-platform compatibility
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# Responsive constants
MIN_WINDOW_WIDTH = 800
MIN_WINDOW_HEIGHT = 600
DEFAULT_WINDOW_WIDTH = 1000
DEFAULT_WINDOW_HEIGHT = 800
SCROLL_AREA_MIN_HEIGHT = 400
CARD_MIN_WIDTH = 300
RESPONSIVE_SPACING = 16
RESPONSIVE_MARGIN = 20

# Font size scaling based on platform
if IS_MAC:
    BASE_FONT_SIZE = 12
else:
    BASE_FONT_SIZE = 10

# ============== MODERN STYLES ==============

# Base font family based on platform
if IS_MAC:
    FONT_FAMILY = "Helvetica Neue, Arial, sans-serif"
elif IS_LINUX:
    FONT_FAMILY = "Ubuntu, Cantarell, DejaVu Sans, Liberation Sans, sans-serif"
else:  # Windows
    FONT_FAMILY = "Segoe UI, Tahoma, Arial, sans-serif"

MAIN_WINDOW_STYLE = f"""
QWidget {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #f8f9fa, stop:1 #e9ecef);
    font-family: {FONT_FAMILY};
}}
"""

INPUT_STYLE = f"""
QLineEdit {{
    background: #ffffff;
    border: 2px solid #dee2e6;
    border-radius: 10px;
    padding: {12 if IS_MAC else 10}px {16 if IS_MAC else 12}px;
    font-size: {14 if IS_MAC else 12}px;
    color: #212529;
    selection-background-color: #4dabf7;
    min-height: {40 if IS_MAC else 36}px;
}}
QLineEdit:hover {{
    border-color: #adb5bd;
    background: #fafafa;
}}
QLineEdit:focus {{
    border-color: #4dabf7;
    background: #ffffff;
    outline: none;
}}
QLineEdit:disabled {{
    background: #f8f9fa;
    color: #adb5bd;
}}
"""

INPUT_ERROR_STYLE = f"""
QLineEdit {{
    background: #fff5f5;
    border: 2px solid #ff6b6b;
    border-radius: 10px;
    padding: {12 if IS_MAC else 10}px {16 if IS_MAC else 12}px;
    font-size: {14 if IS_MAC else 12}px;
    min-height: {40 if IS_MAC else 36}px;
}}
QLineEdit:focus {{
    border-color: #fa5252;
    background: #fff5f5;
}}
"""

INPUT_SUCCESS_STYLE = f"""
QLineEdit {{
    background: #f0fdf4;
    border: 2px solid #51cf66;
    border-radius: 10px;
    padding: {12 if IS_MAC else 10}px {16 if IS_MAC else 12}px;
    font-size: {14 if IS_MAC else 12}px;
    min-height: {40 if IS_MAC else 36}px;
}}
"""

BUTTON_PRIMARY = f"""
QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #51cf66, stop:1 #40c057);
    color: white;
    padding: {14 if IS_MAC else 12}px {32 if IS_MAC else 24}px;
    font-size: {15 if IS_MAC else 13}px;
    font-weight: 600;
    border: none;
    border-radius: 10px;
    min-height: {44 if IS_MAC else 40}px;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #40c057, stop:1 #37b24d);
}}
QPushButton:pressed {{
    background: #2f9e44;
}}
QPushButton:disabled {{
    background: #adb5bd;
    color: #dee2e6;
}}
"""

BUTTON_SECONDARY = f"""
QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #4dabf7, stop:1 #339af0);
    color: white;
    padding: {10 if IS_MAC else 8}px {20 if IS_MAC else 16}px;
    font-size: {13 if IS_MAC else 11}px;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    min-height: {36 if IS_MAC else 32}px;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #339af0, stop:1 #228be6);
}}
QPushButton:pressed {{
    background: #1c7ed6;
}}
"""

BUTTON_DANGER = f"""
QPushButton {{
    background: #ff6b6b;
    color: white;
    font-weight: 600;
    border: none;
    border-radius: 6px;
    padding: {6 if IS_MAC else 4}px;
}}
QPushButton:hover {{
    background: #fa5252;
}}
QPushButton:pressed {{
    background: #f03e3e;
}}
"""

BUTTON_GHOST = f"""
QPushButton {{
    background: transparent;
    color: #495057;
    padding: {10 if IS_MAC else 8}px {20 if IS_MAC else 16}px;
    font-size: {13 if IS_MAC else 11}px;
    border: 2px solid #dee2e6;
    border-radius: 8px;
    min-height: {36 if IS_MAC else 32}px;
}}
QPushButton:hover {{
    background: #f8f9fa;
    border-color: #adb5bd;
    color: #212529;
}}
QPushButton:pressed {{
    background: #e9ecef;
}}
"""

CARD_STYLE = f"""
QFrame {{
    background: white;
    border-radius: 16px;
    border: 1px solid #e9ecef;
    min-width: {CARD_MIN_WIDTH}px;
    margin-bottom: 4px;
}}
"""

LABEL_ERROR = f"""
QLabel {{
    color: #fa5252;
    font-size: {12 if IS_MAC else 10}px;
    padding: 4px 0;
}}
"""

LABEL_SUCCESS = f"""
QLabel {{
    color: #40c057;
    font-size: {12 if IS_MAC else 10}px;
    padding: 4px 0;
}}
"""

# ============== VALIDATION HELPERS ==============

def validate_email(email: str) -> tuple[bool, str]:
    """Validate email with detailed error messages"""
    if not email:
        return False, "Email is required"
    if len(email) > 254:
        return False, "Email is too long"
    if not EMAIL_REGEX.match(email):
        return False, "Invalid email format"
    return True, ""

def validate_ip(ip: str) -> tuple[bool, str]:
    """Validate IP address"""
    if not ip:
        return False, "IP address is required"
    if not IP_REGEX.match(ip):
        return False, "Invalid IP format (e.g., 192.168.1.1)"
    parts = ip.split('.')
    for part in parts:
        if int(part) > 255:
            return False, "IP octets must be 0-255"
    return True, ""


def validate_did(did: str) -> tuple[bool, str]:
    """Validate DID"""
    if not did:
        return False, "DID is required"
    if len(did) < 3:
        return False, "DID must be at least 3 characters"
    if not DID_REGEX.match(did):
        return False, "DID can only contain letters, numbers, - and _"
    return True, ""

# ============== API WORKER THREAD ==============

class APIWorker(QThread):
    """Background thread for API calls"""
    success = Signal(dict)
    error = Signal(str)
    finished = Signal()

    def __init__(self, method: str, url: str, data: Optional[Dict] = None):
        super().__init__()
        self.method = method
        self.url = url
        self.data = data

    def run(self):
        try:
            if self.method == "GET":
                response = requests.get(self.url, timeout=10)
            elif self.method == "PATCH":
                response = requests.patch(self.url, json=self.data, timeout=10)
            else:
                self.error.emit(f"Unsupported method: {self.method}")
                return

            if response.status_code == 200:
                self.success.emit(response.json())
            else:
                error_msg = response.json().get("error", f"HTTP {response.status_code}")
                self.error.emit(error_msg)
        except requests.exceptions.Timeout:
            self.error.emit("Request timed out. Please check your connection.")
        except requests.exceptions.ConnectionError:
            self.error.emit("Cannot connect to server. Is it running?")
        except requests.exceptions.RequestException as e:
            self.error.emit(f"Network error: {str(e)}")
        except Exception as e:
            self.error.emit(f"Unexpected error: {str(e)}")
        finally:
            self.finished.emit()

# ============== ENHANCED COMPONENTS ==============

class ValidatedInput(QWidget):
    """Input field with built-in validation and feedback"""
    
    def __init__(self, label: str, value: str = "", password: bool = False, 
                 validator_func=None, placeholder: str = "", stretch_factor: int = 1):
        super().__init__()
        self.validator_func = validator_func
        self.is_valid = True
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 8)
        layout.setSpacing(6)
        
        # Label
        lbl = QLabel(label)
        lbl.setStyleSheet(f"font-weight: 600; color: #343a40; font-size: {13 if IS_MAC else 11}px; margin-bottom: 2px;")
        layout.addWidget(lbl)
        
        # Input field
        self.input = QLineEdit(value)
        self.input.setStyleSheet(INPUT_STYLE)
        self.input.setPlaceholderText(placeholder)
        
        # Set size policy for responsiveness
        self.input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        if password:
            self.input.setEchoMode(QLineEdit.Password)
        
        # Add show/hide password toggle for password fields
        if password:
            input_container = QHBoxLayout()
            input_container.setContentsMargins(0, 0, 0, 0)
            input_container.addWidget(self.input, stretch=stretch_factor)
            
            self.toggle_btn = QPushButton("👁")
            self.toggle_btn.setFixedWidth(40)
            self.toggle_btn.setStyleSheet(BUTTON_GHOST)
            self.toggle_btn.clicked.connect(self.toggle_password)
            input_container.addWidget(self.toggle_btn)
            
            layout.addLayout(input_container)
        else:
            layout.addWidget(self.input, stretch=stretch_factor)
        
        # Error label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet(LABEL_ERROR)
        self.error_label.hide()
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        
        # Connect validation
        if validator_func:
            self.input.textChanged.connect(self.validate)
    
    def toggle_password(self):
        if self.input.echoMode() == QLineEdit.Password:
            self.input.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setText("🔒")
        else:
            self.input.setEchoMode(QLineEdit.Password)
            self.toggle_btn.setText("👁")
    
    def validate(self, show_error: bool = False) -> bool:
        """Validate input and show/hide error"""
        if not self.validator_func:
            return True
        
        text = self.input.text().strip()
        is_valid, error_msg = self.validator_func(text)
        
        self.is_valid = is_valid
        
        if is_valid:
            self.input.setStyleSheet(INPUT_SUCCESS_STYLE if text else INPUT_STYLE)
            self.error_label.hide()
        elif show_error or text:  # Show error if explicitly requested or if field has content
            self.input.setStyleSheet(INPUT_ERROR_STYLE)
            self.error_label.setText(error_msg)
            self.error_label.show()
        else:
            self.input.setStyleSheet(INPUT_STYLE)
            self.error_label.hide()
        
        return is_valid
    
    def text(self) -> str:
        return self.input.text().strip()
    
    def setText(self, text: str):
        self.input.setText(text)

class Card(QFrame):
    """Enhanced card component with shadow effect"""
    
    def __init__(self, title: str, subtitle: str = ""):
        super().__init__()
        self.setStyleSheet(CARD_STYLE)
        
        # Set size policy for responsiveness
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        
        # Add shadow effect (simulated with border)
        self.setGraphicsEffect(None)  # PySide6 doesn't support drop shadow well
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 32)
        layout.setSpacing(20)
        
        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        
        title_lbl = QLabel(title)
        title_font = QFont()
        title_font.setPointSize(16 if IS_MAC else 14)
        title_font.setBold(True)
        title_lbl.setFont(title_font)
        title_lbl.setStyleSheet(f"color: #212529; font-size: {16 if IS_MAC else 14}px;")
        header.addWidget(title_lbl)
        
        if subtitle:
            subtitle_lbl = QLabel(subtitle)
            subtitle_lbl.setStyleSheet(f"color: #6c757d; font-size: {13 if IS_MAC else 11}px;")
            subtitle_lbl.setWordWrap(True)
            header.addWidget(subtitle_lbl)
        
        layout.addLayout(header)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("background: #e9ecef; max-height: 1px;")
        layout.addWidget(separator)
        
        # Body container
        self.body = QVBoxLayout()
        self.body.setSpacing(12)
        layout.addLayout(self.body)

class DynamicList(QWidget):
    """Enhanced dynamic list with validation"""
    
    def __init__(self, values: List[str], validator_func=None, placeholder: str = ""):
        super().__init__()
        self.entries = []  # List of tuples: (entry_widget, error_label, container_widget)
        self.validator_func = validator_func
        self.placeholder = placeholder
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(12)
        
        # Add existing values
        for v in values:
            self.add_row(v)
        
        # Add button
        self.add_btn = QPushButton("+ Add Entry")
        self.add_btn.setStyleSheet(BUTTON_SECONDARY)
        self.add_btn.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        self.add_btn.setToolTip("Add a new entry to this list")
        self.add_btn.setCursor(Qt.PointingHandCursor)
        self.add_btn.clicked.connect(lambda: self.add_row())
        self.layout.addWidget(self.add_btn, alignment=Qt.AlignLeft | Qt.AlignTop)
        
        # Info label
        self.info_label = QLabel("")
        self.info_label.setStyleSheet(f"color: #6c757d; font-size: {12 if IS_MAC else 10}px; margin-top: 4px; padding: 4px 0;")
        self.layout.addWidget(self.info_label)
        self.update_info()
    
    def add_row(self, value: str = ""):
        row_container = QWidget()
        row = QHBoxLayout(row_container)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        
        # Input field with validation
        entry_widget = QWidget()
        entry_layout = QVBoxLayout(entry_widget)
        entry_layout.setContentsMargins(0, 0, 0, 0)
        entry_layout.setSpacing(4)
        
        e = QLineEdit(value)
        e.setStyleSheet(INPUT_STYLE)
        e.setPlaceholderText(self.placeholder)
        entry_layout.addWidget(e)
        
        error_lbl = QLabel("")
        error_lbl.setStyleSheet(LABEL_ERROR)
        error_lbl.hide()
        error_lbl.setWordWrap(True)
        entry_layout.addWidget(error_lbl)
        
        # Validation
        def validate_entry():
            if self.validator_func and e.text().strip():
                is_valid, msg = self.validator_func(e.text().strip())
                if not is_valid:
                    e.setStyleSheet(INPUT_ERROR_STYLE)
                    error_lbl.setText(msg)
                    error_lbl.show()
                else:
                    e.setStyleSheet(INPUT_SUCCESS_STYLE)
                    error_lbl.hide()
            else:
                e.setStyleSheet(INPUT_STYLE)
                error_lbl.hide()
        
        e.textChanged.connect(validate_entry)
        
        row.addWidget(entry_widget, stretch=1)
        
        # Remove button
        remove = QPushButton("✕")
        remove.setFixedSize(44, 44)
        remove.setStyleSheet(BUTTON_DANGER)
        remove.clicked.connect(lambda: self.remove_row(row_container, e))
        remove.setToolTip("Remove this entry")
        remove.setCursor(Qt.PointingHandCursor)
        row.addWidget(remove, alignment=Qt.AlignTop | Qt.AlignVCenter)
        
        # Insert before the add button and info label
        insert_pos = self.layout.count() - 2
        self.layout.insertWidget(insert_pos, row_container)
        
        # Store entry, error label, and container for easy removal
        self.entries.append((e, error_lbl, row_container))
        self.update_info()
        
        # Focus the new input if empty (user-added)
        if not value:
            e.setFocus()
    
    def remove_row(self, container: QWidget, entry: QLineEdit):
        # Find and remove entry
        for i, (e, lbl, cont) in enumerate(self.entries):
            if e == entry and cont == container:
                self.entries.pop(i)
                break
        
        container.deleteLater()
        self.update_info()
    
    def clear_all(self):
        """Clear all entries from the list"""
        # Remove all entry containers
        for e, lbl, container in self.entries:
            container.deleteLater()
        
        self.entries.clear()
        self.update_info()
    
    def update_info(self):
        count = len([e for e, _, _ in self.entries if e.text().strip()])
        total = len(self.entries)
        if total == 0:
            self.info_label.setText("No entries added yet")
        else:
            self.info_label.setText(f"{count} active entr{'y' if count == 1 else 'ies'} (of {total} total)")
    
    def values(self) -> List[str]:
        """Get all non-empty, valid values"""
        result = []
        for e, _, _ in self.entries:
            text = e.text().strip()
            if text:
                if self.validator_func:
                    is_valid, _ = self.validator_func(text)
                    if is_valid:
                        result.append(text)
                else:
                    result.append(text)
        return result
    
    def validate_all(self) -> bool:
        """Validate all entries"""
        all_valid = True
        for e, error_lbl, _ in self.entries:
            text = e.text().strip()
            if text and self.validator_func:
                is_valid, msg = self.validator_func(text)
                if not is_valid:
                    e.setStyleSheet(INPUT_ERROR_STYLE)
                    error_lbl.setText(msg)
                    error_lbl.show()
                    all_valid = False
                else:
                    e.setStyleSheet(INPUT_SUCCESS_STYLE)
                    error_lbl.hide()
            elif not text:
                e.setStyleSheet(INPUT_STYLE)
                error_lbl.hide()
        return all_valid

# ============== MAIN APPLICATION ==============

class ConfigApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Configuration Manager")
        
        # Set responsive window size based on screen dimensions
        screen = QApplication.primaryScreen().availableGeometry()
        width = min(DEFAULT_WINDOW_WIDTH, screen.width() - 50)
        height = min(900, screen.height() - 100)
        
        self.resize(width, height)
        self.setMinimumSize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
        
        self.setStyleSheet(MAIN_WINDOW_STYLE)
        
        # State
        self.original_config = {}
        self.is_loading = False
        self.unsaved_changes = False
        
        # Handle window resize events
        self.resize_timer = QTimer()
        self.resize_timer.timeout.connect(self.on_window_resized)
        self.resize_timer.setSingleShot(True)
        
        self.setup_ui()
        self.load_configuration()
    
    def setup_ui(self):
        """Setup the UI layout"""
        main = QVBoxLayout(self)
        main.setContentsMargins(RESPONSIVE_MARGIN, RESPONSIVE_MARGIN, RESPONSIVE_MARGIN, RESPONSIVE_MARGIN)
        main.setSpacing(16)
        
        # Header
        header = self.create_header()
        main.addWidget(header)
        
        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background: #f8f9fa;
                width: 12px;
                border-radius: 6px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #ced4da;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #adb5bd;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)
        scroll.setMinimumHeight(SCROLL_AREA_MIN_HEIGHT)
        main.addWidget(scroll)
        
        container = QWidget()
        self.layout = QVBoxLayout(container)
        self.layout.setSpacing(24)
        self.layout.setContentsMargins(4, 4, 4, 4)
        scroll.setWidget(container)
        
        # Email Settings Card
        self.create_email_section()
        
        # Exclusions Cards
        self.create_exclusions_section()
        
        # Footer with actions
        self.create_footer()
    
    def on_window_resized(self):
        """Handle window resize events"""
        # Adjust UI elements based on new window size
        pass
    
    def resizeEvent(self, event):
        """Override resize event to handle responsive behavior"""
        # Use a timer to debounce resize events
        self.resize_timer.stop()
        self.resize_timer.start(100)  # 100ms delay
        super().resizeEvent(event)
    
    def create_header(self) -> QWidget:
        """Create application header"""
        header = QWidget()
        header.setStyleSheet("background: white; border-radius: 16px; border: 1px solid #e9ecef; margin-bottom: 4px;")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)
        
        # Title section
        title_section = QVBoxLayout()
        title_section.setSpacing(6)
        title = QLabel("Configuration Manager")
        title_font = QFont()
        title_font.setPointSize(22 if IS_MAC else 18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet(f"color: #212529; font-size: {22 if IS_MAC else 18}px; letter-spacing: -0.5px;")
        
        subtitle = QLabel("Manage email settings and exclusion rules")
        subtitle.setStyleSheet(f"color: #6c757d; font-size: {14 if IS_MAC else 12}px;")
        
        title_section.addWidget(title)
        title_section.addWidget(subtitle)
        layout.addLayout(title_section)
        
        layout.addStretch()
        
        # Status indicator
        status_container = QWidget()
        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(8)
        
        self.status_label = QLabel("● Connected")
        self.status_label.setStyleSheet(f"""
            color: #51cf66; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #f0fdf4;
            border-radius: 20px;
            border: 1px solid #d3f9d8;
        """)
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_container)
        
        return header
    
    def create_email_section(self):
        """Create email settings card"""
        card = Card(
            "Email Configuration",
            "Set the admin email address for notifications and contact"
        )
        
        self.admin_email = ValidatedInput(
            "Admin Email",
            placeholder="admin@example.com",
            validator_func=validate_email,
            stretch_factor=1
        )
        
        card.body.addWidget(self.admin_email)
        
        self.layout.addWidget(card)
    
    def create_exclusions_section(self):
        """Create exclusion lists cards"""
        # Accounts
        accounts_card = Card(
            "Excluded Accounts",
            "User accounts that will be excluded from monitoring"
        )
        self.accounts = DynamicList(
            [],
            validator_func=lambda x: (len(x) >= 3, "Account name must be at least 3 characters") if x else (True, ""),
            placeholder="Enter account name"
        )
        accounts_card.body.addWidget(self.accounts)
        self.layout.addWidget(accounts_card)
        
        # IPs
        ips_card = Card(
            "Excluded IP Addresses",
            "IP addresses that will be excluded from monitoring"
        )
        self.ips = DynamicList(
            [],
            validator_func=validate_ip,
            placeholder="e.g., 192.168.1.1"
        )
        ips_card.body.addWidget(self.ips)
        self.layout.addWidget(ips_card)
        
        # DIDs
        dids_card = Card(
            "Excluded DIDs",
            "Device IDs that will be excluded from monitoring"
        )
        self.dids = DynamicList(
            [],
            validator_func=validate_did,
            placeholder="Enter device ID"
        )
        dids_card.body.addWidget(self.dids)
        self.layout.addWidget(dids_card)
    
    def create_footer(self):
        """Create footer with action buttons"""
        footer = QWidget()
        footer.setStyleSheet("background: white; border-radius: 16px; border: 1px solid #e9ecef; margin-top: 4px;")
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)
        
        # Reset button
        reset_btn = QPushButton("↺ Reset")
        reset_btn.setStyleSheet(BUTTON_GHOST)
        reset_btn.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        reset_btn.setCursor(Qt.PointingHandCursor)
        reset_btn.setToolTip("Reset all changes to the last saved configuration")
        reset_btn.clicked.connect(self.reset_to_original)
        layout.addWidget(reset_btn)
        
        layout.addStretch()
        
        # Validate button
        validate_btn = QPushButton("✓ Validate")
        validate_btn.setStyleSheet(BUTTON_GHOST)
        validate_btn.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        validate_btn.setCursor(Qt.PointingHandCursor)
        validate_btn.setToolTip("Validate all form fields")
        validate_btn.clicked.connect(self.validate_all_fields)
        layout.addWidget(validate_btn)
        
        # Save button
        self.save_btn = QPushButton("💾 Save Configuration")
        self.save_btn.setStyleSheet(BUTTON_PRIMARY)
        self.save_btn.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.setToolTip("Save configuration to server")
        self.save_btn.clicked.connect(self.save)
        layout.addWidget(self.save_btn)
        
        self.layout.addWidget(footer)
    
    def load_configuration(self):
        """Load configuration from API"""
        self.is_loading = True
        self.save_btn.setEnabled(False)
        self.status_label.setText("● Loading...")
        self.status_label.setStyleSheet(f"""
            color: #ffa500; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #fff4e6;
            border-radius: 20px;
            border: 1px solid #ffe8cc;
        """)
        
        self.worker = APIWorker("GET", API_URL)
        self.worker.success.connect(self.on_config_loaded)
        self.worker.error.connect(self.on_load_error)
        self.worker.finished.connect(lambda: setattr(self, 'is_loading', False))
        self.worker.start()
    
    def on_config_loaded(self, config: Dict[str, Any]):
        """Handle successful configuration load"""
        self.original_config = config
        
        # Populate email fields
        email = config.get("email", {})
        self.admin_email.setText(email.get("admin_email", ""))
        
        # Populate exclusion lists - clear existing entries first
        exclusions = config.get("exclusions", {})
        
        # Clear and repopulate accounts
        self.accounts.clear_all()
        for acc in exclusions.get("accounts", []):
            self.accounts.add_row(acc)
        
        # Clear and repopulate IPs
        self.ips.clear_all()
        for ip in exclusions.get("ips", []):
            self.ips.add_row(ip)
        
        # Clear and repopulate DIDs
        self.dids.clear_all()
        for did in exclusions.get("dids", []):
            self.dids.add_row(did)
        
        self.save_btn.setEnabled(True)
        self.status_label.setText("● Connected")
        self.status_label.setStyleSheet(f"""
            color: #51cf66; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #f0fdf4;
            border-radius: 20px;
            border: 1px solid #d3f9d8;
        """)
        self.unsaved_changes = False
    
    def on_load_error(self, error: str):
        """Handle configuration load error"""
        self.status_label.setText("● Disconnected")
        self.status_label.setStyleSheet(f"""
            color: #ff6b6b; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #fff5f5;
            border-radius: 20px;
            border: 1px solid #ffd6d6;
        """)
        
        QMessageBox.critical(
            self,
            "Connection Error",
            f"Failed to load configuration:\n\n{error}\n\nPlease check if the server is running."
        )
    
    def validate_all_fields(self) -> bool:
        """Validate all form fields"""
        all_valid = True
        
        # Validate email fields
        if not self.admin_email.validate(show_error=True):
            all_valid = False
        
        # Validate dynamic lists
        if not self.accounts.validate_all():
            all_valid = False
        if not self.ips.validate_all():
            all_valid = False
        if not self.dids.validate_all():
            all_valid = False
        
        if all_valid:
            QMessageBox.information(
                self,
                "Validation Successful",
                "✓ All fields are valid and ready to save!"
            )
        else:
            QMessageBox.warning(
                self,
                "Validation Failed",
                "Please correct the errors highlighted in red before saving."
            )
        
        return all_valid
    
    def reset_to_original(self):
        """Reset all fields to original loaded values"""
        reply = QMessageBox.question(
            self,
            "Reset Configuration",
            "Are you sure you want to reset all changes to the last saved configuration?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.on_config_loaded(self.original_config)
    
    def save(self):
        """Save configuration to API"""
        # Validate before saving
        if not self.validate_all_fields():
            return
        
        # Prepare payload
        payload = {
            "admin_email": self.admin_email.text(),
            "exclude_accounts": self.accounts.values(),
            "exclude_ips": self.ips.values(),
            "exclude_dids": self.dids.values(),
        }
        
        # Remove empty values
        payload = {k: v for k, v in payload.items() if v}
        
        # Disable save button during save
        self.save_btn.setEnabled(False)
        self.save_btn.setText("Saving...")
        self.status_label.setText("● Saving...")
        self.status_label.setStyleSheet(f"""
            color: #ffa500; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #fff4e6;
            border-radius: 20px;
            border: 1px solid #ffe8cc;
        """)
        
        # Start API worker
        self.save_worker = APIWorker("PATCH", API_URL, payload)
        self.save_worker.success.connect(self.on_save_success)
        self.save_worker.error.connect(self.on_save_error)
        self.save_worker.finished.connect(self.on_save_finished)
        self.save_worker.start()
    
    def on_save_success(self, response: Dict[str, Any]):
        """Handle successful save"""
        self.original_config = response
        self.unsaved_changes = False
        
        QMessageBox.information(
            self,
            "Success",
            "✓ Configuration saved successfully!"
        )
        
        self.status_label.setText("● Connected")
        self.status_label.setStyleSheet(f"""
            color: #51cf66; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #f0fdf4;
            border-radius: 20px;
            border: 1px solid #d3f9d8;
        """)
    
    def on_save_error(self, error: str):
        """Handle save error"""
        QMessageBox.critical(
            self,
            "Save Failed",
            f"Failed to save configuration:\n\n{error}"
        )
        
        self.status_label.setText("● Error")
        self.status_label.setStyleSheet(f"""
            color: #ff6b6b; 
            font-weight: 600; 
            font-size: {13 if IS_MAC else 11}px;
            padding: 8px 16px;
            background: #fff5f5;
            border-radius: 20px;
            border: 1px solid #ffd6d6;
        """)
    
    def on_save_finished(self):
        """Re-enable save button after save attempt"""
        self.save_btn.setEnabled(True)
        self.save_btn.setText("💾 Save Configuration")
    
    def closeEvent(self, event):
        """Handle window close with unsaved changes warning"""
        if self.unsaved_changes:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes. Are you sure you want to exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
        event.accept()

# ============== APPLICATION ENTRY POINT ==============

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application-wide font based on platform
    if IS_MAC:
        font = QFont("Helvetica Neue", BASE_FONT_SIZE)
    elif IS_LINUX:
        font = QFont("Ubuntu", BASE_FONT_SIZE)
    else:  # Windows
        font = QFont("Segoe UI", BASE_FONT_SIZE)
    
    app.setFont(font)
    
    # Apply platform-specific styling
    if IS_MAC:
        # macOS-specific settings
        app.setStyle('Fusion')  # Use Fusion style for better appearance on macOS
    elif IS_LINUX:
        # Linux-specific settings
        app.setStyle('Fusion')
    
    window = ConfigApp()
    window.show()
    
    sys.exit(app.exec())