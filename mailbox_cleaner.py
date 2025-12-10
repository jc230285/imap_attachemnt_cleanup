#!/usr/bin/env python3
import os
import sys
import csv
import json
import imaplib
import hashlib
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime, timezone, timedelta
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import traceback

# ---------- CONFIG / PATHS ----------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")  # Fallback if not specified in config
STATE_FILE = os.path.join(BASE_DIR, "state.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
FAILURE_LOG = os.path.join(BASE_DIR, "failures.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DEFAULT_ATTACHMENTS_ROOT, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "mail_cleaner.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ---------- GUI PROGRESS WINDOW ----------

class ProgressWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IMAP Mailbox Cleaner - Progress")
        self.root.geometry("1200x800")
        
        # Main progress bar
        main_frame = tk.Frame(self.root)
        main_frame.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(main_frame, text="Overall Progress:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame, variable=self.progress_var, maximum=100, length=1180
        )
        self.progress_bar.pack(pady=5)
        
        self.status_label = tk.Label(main_frame, text="Initializing...", font=("Arial", 11, "bold"))
        self.status_label.pack(pady=5)
        
        # Start time label
        self.start_time_label = tk.Label(main_frame, text="Start Time: --:--:--", font=("Arial", 9))
        self.start_time_label.pack(pady=2)
        
        # Runtime label
        self.start_time = None
        self.runtime_label = tk.Label(main_frame, text="Runtime: 00:00:00", font=("Arial", 9))
        self.runtime_label.pack(pady=2)
        
        # Account progress section
        account_frame = tk.LabelFrame(self.root, text="Account Progress", font=("Arial", 10, "bold"), padx=10, pady=10)
        account_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        # Scrollable canvas for account rows
        canvas = tk.Canvas(account_frame, height=250)
        scrollbar = ttk.Scrollbar(account_frame, orient="vertical", command=canvas.yview)
        self.account_inner_frame = tk.Frame(canvas)
        
        self.account_inner_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.account_inner_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Account tracking
        self.account_widgets = {}  # email -> {frame, progress_bar, status_label, runtime_label, eta_label, stop_button, stop_event, start_time}
        
        # Log area
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(log_frame, text="Activity Log:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, height=15, font=("Consolas", 9), bg="#f5f5f5"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.lock = threading.Lock()
        self.messages_processed = 0
        self.attachments_saved = 0
        
        # Start runtime updater
        self.update_runtime()
        
    def create_account_row(self, email):
        """Create a progress row for an account"""
        row_frame = tk.Frame(self.account_inner_frame, relief=tk.RIDGE, borderwidth=1, padx=5, pady=5)
        row_frame.pack(fill=tk.X, pady=3)
        
        # Email label
        email_label = tk.Label(row_frame, text=email, font=("Arial", 9, "bold"), width=30, anchor=tk.W)
        email_label.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(row_frame, variable=progress_var, maximum=100, length=300)
        progress_bar.pack(side=tk.LEFT, padx=5)
        
        # Status label
        status_label = tk.Label(row_frame, text="Waiting...", font=("Arial", 8), width=20, anchor=tk.W)
        status_label.pack(side=tk.LEFT, padx=5)
        
        # Runtime label
        runtime_label = tk.Label(row_frame, text="Time: --:--:-- | Started: --:--:--", font=("Arial", 8), width=30)
        runtime_label.pack(side=tk.LEFT, padx=5)
        
        # Rate label (emails per minute)
        rate_label = tk.Label(row_frame, text="Rate: -- msg/min", font=("Arial", 8), width=15)
        rate_label.pack(side=tk.LEFT, padx=5)
        
        # ETA label
        eta_label = tk.Label(row_frame, text="ETA: --:--:--", font=("Arial", 8), width=12)
        eta_label.pack(side=tk.LEFT, padx=5)
        
        # Stop button
        stop_event = threading.Event()
        stop_button = tk.Button(row_frame, text="Stop", font=("Arial", 8), width=8,
                                command=lambda: self.stop_account(email))
        stop_button.pack(side=tk.LEFT, padx=5)
        
        self.account_widgets[email] = {
            'frame': row_frame,
            'progress_var': progress_var,
            'progress_bar': progress_bar,
            'status_label': status_label,
            'runtime_label': runtime_label,
            'rate_label': rate_label,
            'eta_label': eta_label,
            'stop_button': stop_button,
            'stop_event': stop_event,
            'start_time': None,
            'total_messages': 0,
            'processed_messages': 0
        }
        
    def stop_account(self, email):
        """Gracefully stop processing for an account"""
        if email in self.account_widgets:
            self.account_widgets[email]['stop_event'].set()
            self.account_widgets[email]['stop_button'].config(state=tk.DISABLED, text="Stopping...")
            self.log(f"⏸ Stop requested for {email}", "WARNING")
            
    def update_account_progress(self, email, progress, status="", total_messages=None, processed_messages=None):
        """Update progress for a specific account"""
        if email not in self.account_widgets:
            self.create_account_row(email)
        
        widgets = self.account_widgets[email]
        
        def _update():
            widgets['progress_var'].set(progress)
            if status:
                widgets['status_label'].config(text=status)
            
            # Update message counts
            if total_messages is not None:
                widgets['total_messages'] = total_messages
            if processed_messages is not None:
                widgets['processed_messages'] = processed_messages
                
            # Calculate ETA
            if widgets['start_time'] and widgets['total_messages'] > 0 and widgets['processed_messages'] > 0:
                elapsed = (datetime.now() - widgets['start_time']).total_seconds()
                rate = widgets['processed_messages'] / elapsed if elapsed > 0 else 0
                remaining = widgets['total_messages'] - widgets['processed_messages']
                
                if rate > 0:
                    eta_seconds = remaining / rate
                    eta_str = str(timedelta(seconds=int(eta_seconds)))
                    widgets['eta_label'].config(text=f"ETA: {eta_str}")
                    
        self.root.after(0, _update)
    
    def start_account(self, email):
        """Mark account as started"""
        if email not in self.account_widgets:
            self.create_account_row(email)
        self.account_widgets[email]['start_time'] = datetime.now()
        self.update_account_progress(email, 0, "Starting...")
        
    def complete_account(self, email, success=True):
        """Mark account as completed"""
        if email in self.account_widgets:
            status = "✓ Completed" if success else "✗ Failed"
            color = "green" if success else "red"
            
            def _update():
                self.account_widgets[email]['status_label'].config(text=status, fg=color)
                self.account_widgets[email]['stop_button'].config(state=tk.DISABLED)
                self.account_widgets[email]['eta_label'].config(text="")
            self.root.after(0, _update)
    
    def update_account_runtime(self):
        """Update runtime and rate for all active accounts"""
        for email, widgets in self.account_widgets.items():
            if widgets['start_time']:
                elapsed = datetime.now() - widgets['start_time']
                runtime_str = str(timedelta(seconds=int(elapsed.total_seconds())))
                start_time_str = widgets['start_time'].strftime("%H:%M:%S")
                widgets['runtime_label'].config(text=f"Time: {runtime_str} | Started: {start_time_str}")
                
                # Calculate messages per minute rate
                elapsed_minutes = elapsed.total_seconds() / 60
                if elapsed_minutes > 0 and widgets['processed_messages'] > 0:
                    rate = widgets['processed_messages'] / elapsed_minutes
                    widgets['rate_label'].config(text=f"Rate: {rate:.1f} msg/min")
        
        # Schedule next update
        self.root.after(1000, self.update_account_runtime)
    
    def update_runtime(self):
        """Update overall runtime"""
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            runtime_str = str(timedelta(seconds=int(elapsed.total_seconds())))
            self.runtime_label.config(text=f"Runtime: {runtime_str}")
            
            # Update start time label if not set
            if "--:--:--" in self.start_time_label.cget("text"):
                start_time_str = self.start_time.strftime("%H:%M:%S")
                self.start_time_label.config(text=f"Start Time: {start_time_str}")
        
        # Schedule next update
        self.root.after(1000, self.update_runtime)
    
    def is_account_stopped(self, email):
        """Check if stop was requested for an account"""
        if email in self.account_widgets:
            return self.account_widgets[email]['stop_event'].is_set()
        return False
        
        # Status label
        self.status_label = tk.Label(self.root, text="Initializing...", font=("Arial", 11, "bold"))
        self.status_label.pack(pady=5)
        
        # Stats frame
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(pady=5)
        
        self.stats_label = tk.Label(stats_frame, text="Accounts: 0/0 | Messages: 0 | Attachments: 0", 
                                     font=("Arial", 9))
        self.stats_label.pack()
        
        # Status info frame - shows last run info and current processing
        info_frame = tk.Frame(self.root, bg="#e8f4f8", relief=tk.RIDGE, borderwidth=2)
        info_frame.pack(pady=5, padx=10, fill=tk.X)
        
        # Current processing info
        current_frame = tk.Frame(info_frame, bg="#e8f4f8")
        current_frame.pack(side=tk.LEFT, padx=10, pady=5)
        tk.Label(current_frame, text="Current Processing:", font=("Arial", 9, "bold"), bg="#e8f4f8").pack(anchor=tk.W)
        self.current_account_label = tk.Label(current_frame, text="Account: None", font=("Arial", 8), bg="#e8f4f8")
        self.current_account_label.pack(anchor=tk.W)
        self.current_date_label = tk.Label(current_frame, text="Email Date: None", font=("Arial", 8), bg="#e8f4f8")
        self.current_date_label.pack(anchor=tk.W)
        
        # Last successful info
        success_frame = tk.Frame(info_frame, bg="#e8f4f8")
        success_frame.pack(side=tk.LEFT, padx=20, pady=5)
        tk.Label(success_frame, text="Last Successful:", font=("Arial", 9, "bold"), bg="#e8f4f8", fg="green").pack(anchor=tk.W)
        self.last_success_label = tk.Label(success_frame, text="None", font=("Arial", 8), bg="#e8f4f8")
        self.last_success_label.pack(anchor=tk.W)
        
        # Last failure info
        failure_frame = tk.Frame(info_frame, bg="#e8f4f8")
        failure_frame.pack(side=tk.LEFT, padx=20, pady=5)
        tk.Label(failure_frame, text="Last Failed:", font=("Arial", 9, "bold"), bg="#e8f4f8", fg="red").pack(anchor=tk.W)
        self.last_failure_label = tk.Label(failure_frame, text="None", font=("Arial", 8), bg="#e8f4f8")
        self.last_failure_label.pack(anchor=tk.W)
        
        # Log area
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(log_frame, text="Activity Log:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, height=25, font=("Consolas", 9), bg="#f5f5f5"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.lock = threading.Lock()
        self.accounts_completed = 0
        self.total_accounts = 0
        self.messages_processed = 0
        self.attachments_saved = 0
        
    def increment_messages(self, count=1):
        self.messages_processed += count
        
    def increment_attachments(self, count=1):
        self.attachments_saved += count
        
    def update_progress(self, value, status=""):
        def _update():
            self.progress_var.set(value)
            if status:
                self.status_label.config(text=status)
        self.root.after(0, _update)
    
    def log(self, message, level="INFO"):
        def _log():
            timestamp = datetime.now().strftime("%H:%M:%S")
            color_tag = ""
            if level == "ERROR":
                color_tag = "error"
            elif level == "SUCCESS":
                color_tag = "success"
            elif level == "WARNING":
                color_tag = "warning"
                
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", color_tag)
            self.log_text.see(tk.END)
        self.root.after(0, _log)
        
    def setup_tags(self):
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("success", foreground="green")
        self.log_text.tag_config("warning", foreground="orange")
    
    def start_async(self):
        """Start processing - GUI runs in main thread"""
        pass  # GUI will be started by mainloop in main()
    
    def close(self):
        self.root.quit()

# ---------- UTILS ----------

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"Missing {CONFIG_FILE}, create it first.")
        sys.exit(1)
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def load_failures():
    if not os.path.exists(FAILURE_LOG):
        return {}
    with open(FAILURE_LOG, "r") as f:
        return json.load(f)

def save_failures(failures):
    with open(FAILURE_LOG, "w") as f:
        json.dump(failures, f, indent=2)

def record_success(account_email, failures):
    if account_email not in failures:
        failures[account_email] = {}
    failures[account_email]["last_success"] = datetime.now(timezone.utc).isoformat()
    failures[account_email]["last_error"] = None
    failures[account_email]["error_message"] = None

def record_failure(account_email, error_msg, failures):
    if account_email not in failures:
        failures[account_email] = {}
    failures[account_email]["last_failure"] = datetime.now(timezone.utc).isoformat()
    failures[account_email]["last_error"] = str(error_msg)[:200]  # Truncate long messages
    failures[account_email]["error_message"] = str(error_msg)

def sanitize_part(s: str) -> str:
    """Sanitize a string for use in file/folder names"""
    if not s:
        return "unknown"
    s = s.replace(" ", "_")
    s = "".join(c for c in s if c.isalnum() or c in "._-")
    return s or "unknown"

def sanitize_email_for_folder(email: str) -> str:
    """Sanitize email address for folder name - replaces @ with _"""
    if not email:
        return "unknown"
    # Replace @ with _ and keep everything else that's safe for folders
    email = email.replace(" ", "_").replace("@", "_")
    email = "".join(c for c in email if c.isalnum() or c in "._-")
    return email or "unknown"

def extract_email_parts(email: str) -> tuple:
    """Extract domain and user parts from an email address"""
    if not email or "@" not in email:
        return "unknown", "unknown"
    
    try:
        user, domain = email.rsplit("@", 1)
        return sanitize_part(domain), sanitize_part(user)
    except Exception:
        return "unknown", "unknown"

def safe_filename(name: str) -> str:
    if not name:
        return "attachment.bin"
    name = name.replace(os.sep, "_")
    return "".join(c for c in name if c.isalnum() or c in "._-")

def parse_email_date(date_header) -> datetime:
    if not date_header:
        return datetime.now(timezone.utc)
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

def load_hash_index(account_email: str, attachments_root: str = None):
    if attachments_root is None:
        attachments_root = DEFAULT_ATTACHMENTS_ROOT
    idx_path = os.path.join(attachments_root, sanitize_email_for_folder(account_email), ".hashes.json")
    if not os.path.exists(idx_path):
        return set(), idx_path
    with open(idx_path, "r") as f:
        data = json.load(f)
    return set(data), idx_path

def save_hash_index(hash_set, idx_path):
    os.makedirs(os.path.dirname(idx_path), exist_ok=True)
    with open(idx_path, "w") as f:
        json.dump(list(hash_set), f)

def save_hash_index_atomic(hash_set, idx_path, lock):
    """Thread-safe hash index saving"""
    with lock:
        # Re-load to merge with any updates from other threads
        existing_hashes = set()
        if os.path.exists(idx_path):
            try:
                with open(idx_path, "r") as f:
                    existing_hashes = set(json.load(f))
            except Exception:
                pass
        
        # Merge and save
        combined = existing_hashes | hash_set
        os.makedirs(os.path.dirname(idx_path), exist_ok=True)
        with open(idx_path, "w") as f:
            json.dump(list(combined), f)

def get_account_csv_path(account_email: str, attachments_root: str = None) -> str:
    """Get the CSV path for a specific account"""
    if attachments_root is None:
        attachments_root = DEFAULT_ATTACHMENTS_ROOT
    acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
    return os.path.join(acc_dir, "downloaded.csv")

def load_downloaded_db(accounts):
    """Load downloaded database from all account CSV files"""
    db = {}
    for account in accounts:
        account_email = account["email"]
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        csv_path = get_account_csv_path(account_email, attachments_root)
        
        if not os.path.exists(csv_path):
            continue
            
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row["account_email"], row["uid"])
                db[key] = row
    return db

def save_downloaded_db(db, accounts):
    """Save downloaded database to per-account CSV files"""
    fieldnames = [
        "account_email",
        "uid",
        "message_id",
        "sent_date",
        "subject",
        "attachments_downloaded",
        "attachments_deleted",
        "attachment_filenames"
    ]
    
    # Group entries by account
    account_data = {}
    for (acc_email, uid), row in db.items():
        if acc_email not in account_data:
            account_data[acc_email] = []
        account_data[acc_email].append(row)
    
    # Save each account's data to its own CSV
    for account in accounts:
        account_email = account["email"]
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        csv_path = get_account_csv_path(account_email, attachments_root)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        
        # Get data for this account
        rows = account_data.get(account_email, [])
        
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

def calculate_age_days(sent_dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    delta = now - sent_dt
    return delta.days

def deduplicate_all_accounts(accounts, progress_window=None):
    """
    Deduplicate files across ALL account folders.
    Keeps only the oldest (first created) file for each hash.
    """
    if progress_window:
        progress_window.log("\n--- Starting Global Deduplication ---")
    
    # Build a global hash map: hash -> (file_path, creation_time)
    hash_map = {}
    total_files = 0
    
    # Scan all account folders
    for account in accounts:
        account_email = account["email"]
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
        
        if not os.path.exists(acc_dir):
            continue
        
        # Walk through all files in this account folder
        for root, dirs, files in os.walk(acc_dir):
            for filename in files:
                # Skip metadata files
                if filename in ['.hashes.json', 'downloaded.csv']:
                    continue
                
                filepath = os.path.join(root, filename)
                total_files += 1
                
                try:
                    # Calculate hash
                    with open(filepath, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                    
                    # Get file creation time (oldest timestamp)
                    creation_time = os.path.getctime(filepath)
                    
                    # Track the oldest file for each hash
                    if file_hash not in hash_map:
                        hash_map[file_hash] = (filepath, creation_time)
                    else:
                        existing_path, existing_time = hash_map[file_hash]
                        # Keep the older file
                        if creation_time < existing_time:
                            hash_map[file_hash] = (filepath, creation_time)
                
                except Exception as e:
                    logging.warning(f"Error processing {filepath}: {e}")
    
    # Now find and remove duplicates
    duplicates_removed = 0
    space_freed = 0
    
    for account in accounts:
        account_email = account["email"]
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
        
        if not os.path.exists(acc_dir):
            continue
        
        for root, dirs, files in os.walk(acc_dir):
            for filename in files:
                if filename in ['.hashes.json', 'downloaded.csv']:
                    continue
                
                filepath = os.path.join(root, filename)
                
                try:
                    with open(filepath, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                    
                    # If this file is NOT the keeper, delete it
                    keeper_path, _ = hash_map[file_hash]
                    if filepath != keeper_path:
                        file_size = os.path.getsize(filepath)
                        os.remove(filepath)
                        duplicates_removed += 1
                        space_freed += file_size
                        logging.info(f"Removed duplicate: {filepath} (kept {keeper_path})")
                
                except Exception as e:
                    logging.warning(f"Error removing duplicate {filepath}: {e}")
    
    # Remove empty folders after deduplication
    empty_folders_removed = 0
    for account in accounts:
        account_email = account["email"]
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
        
        if not os.path.exists(acc_dir):
            continue
        
        # Walk bottom-up to remove empty folders
        for root, dirs, files in os.walk(acc_dir, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    # Check if directory is empty (no files, no subdirectories)
                    if not os.listdir(dir_path):
                        os.rmdir(dir_path)
                        empty_folders_removed += 1
                        logging.info(f"Removed empty folder: {dir_path}")
                except Exception as e:
                    logging.warning(f"Error removing empty folder {dir_path}: {e}")
    
    # Log results
    space_freed_mb = space_freed / (1024 * 1024)
    msg = f"Deduplication complete: {duplicates_removed} duplicates removed, {space_freed_mb:.2f} MB freed"
    if empty_folders_removed > 0:
        msg += f", {empty_folders_removed} empty folders removed"
    logging.info(msg)
    if progress_window:
        progress_window.log(f"✓ {msg}", "SUCCESS")
    
    return duplicates_removed, space_freed

# ---------- IMAP HELPERS ----------

def connect_imap(account):
    host = account["imap_host"]
    username = account["username"]
    password = account["password"]

    logging.info(f"Connecting to IMAP for {username} @ {host}")
    imap = imaplib.IMAP4_SSL(host)
    imap.login(username, password)
    return imap

def select_all_mail(imap):
    typ, _ = imap.select('"[Gmail]/All Mail"')
    if typ != "OK":
        logging.warning("Could not select [Gmail]/All Mail, falling back to INBOX")
        imap.select("INBOX")

# ---------- TASK 1: DOWNLOAD ATTACHMENTS ----------

# Global locks for thread-safe operations
hash_index_lock = threading.Lock()
state_lock = threading.Lock()
db_lock = threading.Lock()

# Global variable to store accounts for auto-save
GLOBAL_ACCOUNTS = []

def process_new_emails_for_account(account, state, downloaded_db, progress_window=None, failures=None):
    account_email = account["email"]
    imap = None
    
    # Check if this account has failed before
    if failures and account_email in failures:
        last_error = failures[account_email].get("last_error")
        if last_error:
            msg = f"⊗ Skipping {account_email} - previous failure: {last_error}"
            logging.warning(msg)
            if progress_window:
                progress_window.log(msg, "WARNING")
            return 'failed'
    
    try:
        if progress_window:
            progress_window.log(f"→ Connecting to {account_email}...")
            progress_window.start_account(account_email)
        
        imap = connect_imap(account)
        select_all_mail(imap)

        # Thread-safe read of account state
        with state_lock:
            acc_state = state.get(account_email, {}).copy()  # Make a copy to avoid race conditions
        last_uid = acc_state.get("last_processed_uid")
        last_date = acc_state.get("last_processed_date")

        if last_uid:
            search_criteria = f"(UID {int(last_uid) + 1}:*)"
            start_msg = f"Resuming from UID {int(last_uid) + 1} (last processed: {last_date or 'unknown'})"
        else:
            search_criteria = "ALL"
            start_msg = "Starting from beginning (first run)"

        logging.info(f"[{account_email}] {start_msg}")
        logging.info(f"[{account_email}] Searching with {search_criteria}")
        if progress_window:
            progress_window.log(f"  {start_msg}")
        
        typ, data = imap.uid("SEARCH", None, search_criteria)
        if typ != "OK":
            error_msg = f"UID SEARCH failed"
            logging.error(f"[{account_email}] {error_msg}")
            if failures:
                record_failure(account_email, error_msg, failures)
            if progress_window:
                progress_window.log(f"✗ {account_email}: {error_msg}", "ERROR")
                progress_window.complete_account(account_email, success=False)
            return 'failed'

        uids = data[0].split()
        if not uids:
            msg = f"✓ {account_email}: No new messages"
            logging.info(f"[{account_email}] No new messages to process")
            if progress_window:
                progress_window.log(msg, "SUCCESS")
                progress_window.complete_account(account_email, success=True)
            if failures:
                record_success(account_email, failures)
            return 'success'

        total_uids = len(uids)
        if progress_window:
            progress_window.log(f"Processing {total_uids} messages for {account_email}")
            progress_window.update_account_progress(account_email, 0, "Processing...", total_messages=total_uids, processed_messages=0)

        # Get custom folder path from account config, fallback to default
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        os.makedirs(attachments_root, exist_ok=True)
        
        known_hashes, hash_idx_path = load_hash_index(account_email, attachments_root)
        acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
        # Don't create acc_dir here - only create when we actually save attachments

        attachments_in_account = 0
        new_hashes = set()  # Track new hashes found in this run
        
        for idx, uid in enumerate(uids, 1):
            # Check if stop was requested
            if progress_window and progress_window.is_account_stopped(account_email):
                logging.warning(f"[{account_email}] Stop requested by user")
                if progress_window:
                    progress_window.log(f"⏸ {account_email}: Stopped by user", "WARNING")
                    progress_window.complete_account(account_email, success=False)
                # Save progress before stopping
                with state_lock:
                    if idx > 1:  # Only save if we processed at least one message
                        acc_state["last_processed_uid"] = int(uids[idx-2].decode())
                        state[account_email] = acc_state
                    save_state(state)
                with db_lock:
                    save_downloaded_db(downloaded_db, GLOBAL_ACCOUNTS)
                return 'stopped'  # Return special status for graceful stop
            
            uid_str = uid.decode()
            logging.info(f"[{account_email}] Processing UID {uid_str} ({idx}/{total_uids})")
            
            # Update progress
            progress_pct = (idx / total_uids) * 100
            if progress_window:
                progress_window.update_account_progress(account_email, progress_pct, f"Message {idx}/{total_uids}", 
                                                        total_messages=total_uids, processed_messages=idx)

            typ, msg_data = imap.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                logging.warning(f"[{account_email}] Failed to fetch UID {uid_str}")
                continue

            raw_msg = msg_data[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw_msg)

            sent_dt = parse_email_date(msg.get("Date"))
            sent_date_iso = sent_dt.astimezone(timezone.utc).isoformat()

            from_email = parseaddr(msg.get("From", ""))[1] or "unknown"
            to_email = parseaddr(msg.get("To", ""))[1] or "unknown"
            subject = msg.get("Subject", "")

            # Determine which email to use for folder organization
            if from_email.lower() == account_email.lower():
                party_email = to_email
            else:
                party_email = from_email
            
            # Extract domain and user parts
            domain, user = extract_email_parts(party_email)
            
            # Create folder structure: attachments/{account}/{domain}/{user}/
            dest_dir = os.path.join(acc_dir, domain, user)
            # Don't create dest_dir yet - only create when we actually have attachments to save

            attachment_filenames = []
            any_attachments = False
            any_downloaded = False

            for part in msg.walk():
                if part.is_multipart():
                    continue

                filename = part.get_filename()
                content_disposition = (part.get("Content-Disposition") or "").lower()

                if not filename and "attachment" not in content_disposition:
                    continue

                content = part.get_payload(decode=True)
                if not content:
                    continue

                any_attachments = True
                md5 = hashlib.md5(content).hexdigest()

                # Thread-safe check: reload hash index to catch concurrent updates
                with hash_index_lock:
                    # Reload to get latest from disk (in case another thread added it)
                    current_hashes, _ = load_hash_index(account_email, attachments_root)
                    
                    if md5 in current_hashes or md5 in new_hashes:
                        logging.info(f"[{account_email}] UID {uid_str} attachment duplicate (hash: {md5[:8]}...), skipping")
                        continue
                    
                    # Mark as new so we don't save it again in this same run
                    new_hashes.add(md5)

                # Create destination directory AND account directory only when we have a unique attachment to save
                os.makedirs(dest_dir, exist_ok=True)
                # Ensure account directory exists too
                os.makedirs(acc_dir, exist_ok=True)

                date_prefix = sent_dt.astimezone(timezone.utc).strftime("%Y%m%d_%H%M")
                base_name = safe_filename(filename or "attachment.bin")
                final_name = f"{date_prefix}_{base_name}"
                full_path = os.path.join(dest_dir, final_name)

                counter = 2
                while os.path.exists(full_path):
                    name_no_ext, ext = os.path.splitext(base_name)
                    final_name = f"{date_prefix}_{name_no_ext}_{counter}{ext}"
                    full_path = os.path.join(dest_dir, final_name)
                    counter += 1

                with open(full_path, "wb") as f:
                    f.write(content)

                logging.info(f"[{account_email}] Saved: {final_name}")
                attachment_filenames.append(final_name)
                any_downloaded = True
                attachments_in_account += 1
                
                if progress_window:
                    progress_window.increment_attachments()

            if any_attachments:
                key = (account_email, uid_str)
                entry = downloaded_db.get(key, {
                    "account_email": account_email,
                    "uid": uid_str,
                    "message_id": msg.get("Message-ID", ""),
                    "sent_date": sent_date_iso,
                    "subject": subject,
                    "attachments_downloaded": "0",
                    "attachments_deleted": "0",
                    "attachment_filenames": ""
                })

                if any_downloaded:
                    entry["attachments_downloaded"] = "1"

                existing_files = [x for x in entry["attachment_filenames"].split(";") if x]
                existing_files.extend(attachment_filenames)
                entry["attachment_filenames"] = ";".join(sorted(set(existing_files)))

                # Thread-safe database update
                with db_lock:
                    downloaded_db[key] = entry

            # Thread-safe state update
            with state_lock:
                acc_state["last_processed_uid"] = int(uid_str)
                acc_state["last_processed_date"] = sent_date_iso
                state[account_email] = acc_state
            
            if progress_window:
                progress_window.increment_messages()

        # Save hash index with thread safety
        if new_hashes:
            save_hash_index_atomic(new_hashes, hash_idx_path, hash_index_lock)
        
        if failures:
            record_success(account_email, failures)
        
        # Save state and DB immediately after processing this account
        with state_lock:
            save_state(state)
        with db_lock:
            save_downloaded_db(downloaded_db, GLOBAL_ACCOUNTS)
        save_failures(failures)
        
        if progress_window:
            progress_window.log(f"✓ {account_email}: Completed ({attachments_in_account} attachments saved)", "SUCCESS")
            progress_window.complete_account(account_email, success=True)
        
        return 'success'

    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        logging.error(f"[{account_email}] {error_msg}")
        logging.error(traceback.format_exc())
        if progress_window:
            progress_window.log(f"✗ {account_email}: {error_msg}", "ERROR")
            progress_window.complete_account(account_email, success=False)
        if failures:
            record_failure(account_email, error_msg, failures)
        return 'failed'
        
    finally:
        if imap is not None:
            try:
                imap.close()
            except Exception:
                pass
            try:
                imap.logout()
            except Exception:
                pass

# ---------- TASK 2: DELETE ATTACHMENTS AFTER RETENTION ----------

def strip_attachments_from_email(raw_msg_bytes, sent_dt: datetime):
    msg = BytesParser(policy=policy.default).parsebytes(raw_msg_bytes)
    text_chunks = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in content_disposition or part.get_filename():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            text_chunks.append(payload.decode(errors="ignore"))
        except Exception:
            continue

    body = "\n".join(text_chunks).strip()
    note = f"\n\n[Attachments Deleted] Attachments were removed by automated cleanup on {datetime.now(timezone.utc).isoformat()}."
    if body:
        body = body + note
    else:
        body = note.lstrip()

    from email.message import EmailMessage
    new_msg = EmailMessage()
    for h in ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To", "References"]:
        if msg.get(h):
            new_msg[h] = msg.get(h)

    new_msg["X-Attachments-Deleted"] = "yes"
    new_msg.set_content(body)

    return new_msg

def delete_old_attachments_for_account(account, state, downloaded_db, progress_window=None):
    retention_days = account.get("retention_days", -1)
    if retention_days is None or retention_days < 0:
        return

    account_email = account["email"]
    imap = None
    try:
        imap = connect_imap(account)
        select_all_mail(imap)

        deleted_count = 0
        
        for (acc, uid), row in list(downloaded_db.items()):
            if acc != account_email:
                continue

            if row.get("attachments_downloaded") != "1":
                continue

            if row.get("attachments_deleted") == "1":
                continue

            sent_date_iso = row.get("sent_date")
            try:
                sent_dt = datetime.fromisoformat(sent_date_iso)
                if sent_dt.tzinfo is None:
                    sent_dt = sent_dt.replace(tzinfo=timezone.utc)
            except Exception:
                sent_dt = datetime.now(timezone.utc)

            age_days = calculate_age_days(sent_dt)
            if age_days < retention_days:
                continue

            uid_bytes = uid.encode()
            logging.info(f"[{account_email}] Stripping attachments for UID {uid} (age {age_days} days)")

            typ, msg_data = imap.uid("FETCH", uid_bytes, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                logging.warning(f"[{account_email}] Failed to fetch UID {uid} for deletion")
                continue

            raw_msg = msg_data[0][1]
            new_msg = strip_attachments_from_email(raw_msg, sent_dt)
            new_bytes = new_msg.as_bytes()

            date_time = imaplib.Time2Internaldate(sent_dt.timetuple())
            typ, _ = imap.append('"[Gmail]/All Mail"', None, date_time, new_bytes)
            if typ != "OK":
                logging.error(f"[{account_email}] Failed to APPEND cleaned message for UID {uid}")
                continue

            imap.uid("STORE", uid_bytes, "+FLAGS", r"(\Deleted)")
            imap.expunge()

            row["attachments_deleted"] = "1"
            downloaded_db[(acc, uid)] = row
            deleted_count += 1

        if progress_window and deleted_count > 0:
            progress_window.log(f"  Deleted {deleted_count} old attachments from {account_email}")

    except Exception as e:
        logging.error(f"[{account_email}] Error in deletion: {str(e)}")
        if progress_window:
            progress_window.log(f"⚠ {account_email}: Deletion error - {str(e)}", "WARNING")
            
    finally:
        if imap is not None:
            try:
                imap.close()
            except Exception:
                pass
            try:
                imap.logout()
            except Exception:
                pass

# ---------- MAIN ----------

def auto_save_timer(state, downloaded_db, failures, stop_event):
    """Auto-save state and database every 60 seconds"""
    while not stop_event.is_set():
        stop_event.wait(60)  # Wait 60 seconds or until stopped
        if not stop_event.is_set():
            try:
                with state_lock:
                    save_state(state)
                with db_lock:
                    save_downloaded_db(downloaded_db, GLOBAL_ACCOUNTS)
                save_failures(failures)
                logging.info("Auto-saved state and database")
            except Exception as e:
                logging.error(f"Auto-save failed: {str(e)}")

def process_account_wrapper(account, state, downloaded_db, progress_window, failures):
    """Wrapper for concurrent processing"""
    result = process_new_emails_for_account(account, state, downloaded_db, progress_window, failures)
    if progress_window:
        progress_window.increment_account()
    return (account["email"], result)

def main():
    # Create and start GUI
    progress_window = ProgressWindow()
    progress_window.setup_tags()
    
    # Run processing in a background thread
    def run_processing():
        try:
            progress_window.log("=== IMAP Mailbox Cleaner Started ===")
            progress_window.update_progress(0, "Loading configuration...")
            
            config = load_config()
            state = load_state()
            failures = load_failures()

            accounts = config.get("accounts", [])
            if not accounts:
                progress_window.log("No accounts configured in config.json", "ERROR")
                progress_window.update_progress(100, "Error: No accounts configured")
                return
            
            # Set global accounts for auto-save
            global GLOBAL_ACCOUNTS
            GLOBAL_ACCOUNTS = accounts
            
            downloaded_db = load_downloaded_db(accounts)

            # Display last run information
            progress_window.log("\n--- Previous Run Information ---")
            for account in accounts:
                email = account["email"]
                
                # Show last processed state
                if email in state:
                    last_uid = state[email].get("last_processed_uid", "None")
                    last_date = state[email].get("last_processed_date", "None")
                    progress_window.log(f"  {email}: Last UID={last_uid}, Date={last_date}")
                else:
                    progress_window.log(f"  {email}: No previous state (first run)")
                
                # Show failure info if exists
                if email in failures:
                    last_success = failures[email].get("last_success")
                    last_failure = failures[email].get("last_failure")
                    last_error = failures[email].get("last_error")
                    
                    if last_success:
                        progress_window.log(f"    ✓ Last success: {last_success}", "SUCCESS")
                    if last_failure and last_error:
                        progress_window.log(f"    ✗ Last failure: {last_failure} - {last_error}", "ERROR")
            
            progress_window.log("--- End Previous Run Information ---\n")
            
            # Create account rows in GUI
            for account in accounts:
                progress_window.create_account_row(account["email"])
            
            # Start auto-save timer
            stop_auto_save = threading.Event()
            auto_save_thread = threading.Thread(
                target=auto_save_timer,
                args=(state, downloaded_db, failures, stop_auto_save),
                daemon=True
            )
            auto_save_thread.start()
            progress_window.log("Auto-save enabled (every 60 seconds)\n")

            progress_window.log(f"Found {len(accounts)} account(s) to process")
            progress_window.update_progress(10, f"Processing {len(accounts)} accounts...")

            # Use ThreadPoolExecutor for concurrent processing
            max_workers = min(3, len(accounts))  # Limit to 3 concurrent connections
            progress_window.log(f"Using {max_workers} concurrent worker(s)")
            
            successful_accounts = []
            failed_accounts = []
            stopped_accounts = []
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for account in accounts:
                    future = executor.submit(
                        process_new_emails_for_account,
                        account,
                        state,
                        downloaded_db,
                        progress_window,
                        failures
                    )
                    futures[future] = account["email"]
                
                completed = 0
                for future in as_completed(futures):
                    email = futures[future]
                    try:
                        result = future.result()
                        completed += 1
                        progress = 10 + (completed / len(accounts)) * 40  # 10% to 50%
                        progress_window.update_progress(progress, f"Downloaded: {completed}/{len(accounts)}")
                        
                        if result == 'success':
                            successful_accounts.append(email)
                        elif result == 'stopped':
                            stopped_accounts.append(email)
                        else:  # 'failed'
                            failed_accounts.append(email)
                        
                    except Exception as e:
                        progress_window.log(f"✗ Unexpected error for {email}: {str(e)}", "ERROR")
                        failed_accounts.append(email)
                        logging.error(f"Unexpected error for {email}: {traceback.format_exc()}")

            # Save state and failures after downloads
            progress_window.update_progress(55, "Saving state...")
            save_state(state)
            save_downloaded_db(downloaded_db, accounts)
            save_failures(failures)

            # Run global deduplication across all accounts
            progress_window.update_progress(57, "Deduplicating across all accounts...")
            deduplicate_all_accounts(accounts, progress_window)

            # Task 2: Deletion (sequential to avoid conflicts)
            progress_window.update_progress(60, "Processing retention deletions...")
            progress_window.log("--- Starting retention-based deletion ---")
            
            for idx, account in enumerate(accounts, 1):
                email_addr = account["email"]
                if email_addr in failed_accounts:
                    progress_window.log(f"⊗ Skipping deletion for {email_addr} (download failed)")
                    continue
                if email_addr in stopped_accounts:
                    progress_window.log(f"⏸ Skipping deletion for {email_addr} (stopped by user)")
                    continue
                progress_window.log(f"→ Checking retention for {email_addr}...")
                delete_old_attachments_for_account(account, state, downloaded_db, progress_window)
                
                progress = 60 + (idx / len(accounts)) * 30  # 60% to 90%
                progress_window.update_progress(progress, f"Retention: {idx}/{len(accounts)}")

            # Final save
            progress_window.update_progress(95, "Finalizing...")
            save_state(state)
            save_downloaded_db(downloaded_db, accounts)
            save_failures(failures)
            
            # Stop auto-save timer
            stop_auto_save.set()

            # Summary
            progress_window.update_progress(100, "Completed!")
            progress_window.log("=" * 50)
            progress_window.log(f"=== COMPLETED ===", "SUCCESS")
            progress_window.log(f"Successful accounts: {len(successful_accounts)}")
            if stopped_accounts:
                progress_window.log(f"Stopped accounts: {len(stopped_accounts)}", "WARNING")
                progress_window.log(f"Stopped: {', '.join(stopped_accounts)}", "WARNING")
            progress_window.log(f"Failed accounts: {len(failed_accounts)}")
            if failed_accounts:
                progress_window.log(f"Failed: {', '.join(failed_accounts)}", "ERROR")
            progress_window.log("=" * 50)
            progress_window.log("You can close this window now.")
            
            logging.info("Run completed.")
            
        except Exception as e:
            progress_window.log(f"FATAL ERROR: {str(e)}", "ERROR")
            logging.error(f"Fatal error: {traceback.format_exc()}")
    
    # Start processing in background thread
    processing_thread = threading.Thread(target=run_processing, daemon=True)
    processing_thread.start()
    
    # Run GUI in main thread
    progress_window.root.mainloop()

if __name__ == "__main__":
    main()
