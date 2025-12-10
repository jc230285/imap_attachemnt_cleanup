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
from datetime import datetime, timezone
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
        self.root.geometry("1000x700")
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.root, variable=self.progress_var, maximum=100, length=980
        )
        self.progress_bar.pack(pady=10, padx=10)
        
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
        
    def set_total_accounts(self, total):
        self.total_accounts = total
        self.update_stats()
        
    def increment_account(self):
        self.accounts_completed += 1
        self.update_stats()
        
    def increment_messages(self, count=1):
        self.messages_processed += count
        self.update_stats()
        
    def increment_attachments(self, count=1):
        self.attachments_saved += count
        self.update_stats()
        
    def update_stats(self):
        def _update():
            self.stats_label.config(
                text=f"Accounts: {self.accounts_completed}/{self.total_accounts} | "
                     f"Messages: {self.messages_processed} | "
                     f"Attachments: {self.attachments_saved}"
            )
        self.root.after(0, _update)
    
    def update_current_processing(self, account, email_date=None):
        def _update():
            self.current_account_label.config(text=f"Account: {account}")
            if email_date:
                self.current_date_label.config(text=f"Email Date: {email_date}")
            else:
                self.current_date_label.config(text="Email Date: None")
        self.root.after(0, _update)
    
    def update_last_successful(self, account, date_str):
        def _update():
            self.last_success_label.config(text=f"{account}\n{date_str}")
        self.root.after(0, _update)
    
    def update_last_failed(self, account, date_str, error):
        def _update():
            self.last_failure_label.config(text=f"{account}\n{date_str}\n{error[:50]}")
        self.root.after(0, _update)
        
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
            return False
    
    try:
        if progress_window:
            progress_window.log(f"→ Connecting to {account_email}...")
        
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
            return False

        uids = data[0].split()
        if not uids:
            msg = f"✓ {account_email}: No new messages"
            logging.info(f"[{account_email}] No new messages to process")
            if progress_window:
                progress_window.log(msg, "SUCCESS")
            if failures:
                record_success(account_email, failures)
            return True

        total_uids = len(uids)
        if progress_window:
            progress_window.log(f"Processing {total_uids} messages for {account_email}")

        # Get custom folder path from account config, fallback to default
        attachments_root = account.get("folder", DEFAULT_ATTACHMENTS_ROOT)
        os.makedirs(attachments_root, exist_ok=True)
        
        known_hashes, hash_idx_path = load_hash_index(account_email, attachments_root)
        acc_dir = os.path.join(attachments_root, sanitize_email_for_folder(account_email))
        # Don't create acc_dir here - only create when we actually save attachments

        attachments_in_account = 0
        new_hashes = set()  # Track new hashes found in this run
        
        for idx, uid in enumerate(uids, 1):
            uid_str = uid.decode()
            logging.info(f"[{account_email}] Processing UID {uid_str} ({idx}/{total_uids})")

            typ, msg_data = imap.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                logging.warning(f"[{account_email}] Failed to fetch UID {uid_str}")
                continue

            raw_msg = msg_data[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw_msg)

            sent_dt = parse_email_date(msg.get("Date"))
            sent_date_iso = sent_dt.astimezone(timezone.utc).isoformat()
            
            # Update GUI with current processing info
            if progress_window:
                progress_window.update_current_processing(account_email, sent_date_iso)

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
        
        return True

    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        logging.error(f"[{account_email}] {error_msg}")
        logging.error(traceback.format_exc())
        if progress_window:
            progress_window.log(f"✗ {account_email}: {error_msg}", "ERROR")
        if failures:
            record_failure(account_email, error_msg, failures)
        return False
        
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
                        progress_window.update_last_successful(email, last_success)
                        progress_window.log(f"    ✓ Last success: {last_success}", "SUCCESS")
                    if last_failure and last_error:
                        progress_window.update_last_failed(email, last_failure, last_error)
                        progress_window.log(f"    ✗ Last failure: {last_failure} - {last_error}", "ERROR")
            
            progress_window.log("--- End Previous Run Information ---\n")
            
            # Start auto-save timer
            stop_auto_save = threading.Event()
            auto_save_thread = threading.Thread(
                target=auto_save_timer,
                args=(state, downloaded_db, failures, stop_auto_save),
                daemon=True
            )
            auto_save_thread.start()
            progress_window.log("Auto-save enabled (every 60 seconds)\n")

            progress_window.set_total_accounts(len(accounts))
            progress_window.log(f"Found {len(accounts)} account(s) to process")
            progress_window.update_progress(10, f"Processing {len(accounts)} accounts...")

            # Use ThreadPoolExecutor for concurrent processing
            max_workers = min(3, len(accounts))  # Limit to 3 concurrent connections
            progress_window.log(f"Using {max_workers} concurrent worker(s)")
            
            successful_accounts = []
            failed_accounts = []
            
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
                        success = future.result()
                        completed += 1
                        progress = 10 + (completed / len(accounts)) * 40  # 10% to 50%
                        progress_window.update_progress(progress, f"Downloaded: {completed}/{len(accounts)}")
                        
                        if success:
                            successful_accounts.append(email)
                        else:
                            failed_accounts.append(email)
                            
                        progress_window.increment_account()
                        
                    except Exception as e:
                        progress_window.log(f"✗ Unexpected error for {email}: {str(e)}", "ERROR")
                        failed_accounts.append(email)
                        logging.error(f"Unexpected error for {email}: {traceback.format_exc()}")

            # Save state and failures after downloads
            progress_window.update_progress(55, "Saving state...")
            save_state(state)
            save_downloaded_db(downloaded_db, accounts)
            save_failures(failures)

            # Task 2: Deletion (sequential to avoid conflicts)
            progress_window.update_progress(60, "Processing retention deletions...")
            progress_window.log("--- Starting retention-based deletion ---")
            
            for idx, account in enumerate(accounts, 1):
                if account["email"] in failed_accounts:
                    progress_window.log(f"⊗ Skipping deletion for {account['email']} (download failed)")
                    continue
                    
                email_addr = account["email"]
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
