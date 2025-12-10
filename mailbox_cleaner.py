#!/usr/bin/env python3
import os
import sys
import csv
import json
import imaplib
import hashlib
import logging
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr

# ---------- CONFIG / PATHS ----------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")
STATE_FILE = os.path.join(BASE_DIR, "state.json")
DOWNLOADED_CSV = os.path.join(BASE_DIR, "downloaded.csv")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ATTACHMENTS_ROOT, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "mail_cleaner.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

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

def sanitize_part(s: str) -> str:
    if not s:
        return "unknown"
    # basic sanitisation
    s = s.replace("@", "_")
    s = s.replace(" ", "_")
    s = "".join(c for c in s if c.isalnum() or c in "._-")
    return s or "unknown"

def safe_filename(name: str) -> str:
    if not name:
        return "attachment.bin"
    name = name.replace(os.sep, "_")
    return "".join(c for c in name if c.isalnum() or c in "._-")

def parse_email_date(date_header) -> datetime:
    if not date_header:
        # fallback: now
        return datetime.now(timezone.utc)
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

def load_hash_index(account_email: str):
    idx_path = os.path.join(ATTACHMENTS_ROOT, sanitize_part(account_email), ".hashes.json")
    if not os.path.exists(idx_path):
        return set(), idx_path
    with open(idx_path, "r") as f:
        data = json.load(f)
    return set(data), idx_path

def save_hash_index(hash_set, idx_path):
    with open(idx_path, "w") as f:
        json.dump(list(hash_set), f)

def load_downloaded_db():
    db = {}
    if not os.path.exists(DOWNLOADED_CSV):
        return db
    with open(DOWNLOADED_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row["account_email"], row["uid"])
            db[key] = row
    return db

def save_downloaded_db(db):
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
    with open(DOWNLOADED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in db.values():
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
    # For Gmail, "[Gmail]/All Mail" usually works. Fallback to "INBOX" if it fails.
    typ, _ = imap.select('"[Gmail]/All Mail"')
    if typ != "OK":
        logging.warning("Could not select [Gmail]/All Mail, falling back to INBOX")
        imap.select("INBOX")

# ---------- TASK 1: DOWNLOAD ATTACHMENTS ----------

def process_new_emails_for_account(account, state, downloaded_db):
    account_email = account["email"]
    imap = None
    try:
        imap = connect_imap(account)
        select_all_mail(imap)

        acc_state = state.get(account_email, {})
        last_uid = acc_state.get("last_processed_uid")

        if last_uid:
            search_criteria = f"(UID {int(last_uid) + 1}:*)"
        else:
            search_criteria = "ALL"

        logging.info(f"[{account_email}] Searching with {search_criteria}")
        typ, data = imap.uid("SEARCH", None, search_criteria)
        if typ != "OK":
            logging.error(f"[{account_email}] UID SEARCH failed")
            return

        uids = data[0].split()
        if not uids:
            logging.info(f"[{account_email}] No new messages to process")
            return

        known_hashes, hash_idx_path = load_hash_index(account_email)
        acc_dir = os.path.join(ATTACHMENTS_ROOT, sanitize_part(account_email))
        os.makedirs(acc_dir, exist_ok=True)

        for uid in uids:
            uid_str = uid.decode()
            logging.info(f"[{account_email}] Processing UID {uid_str}")

            # fetch whole message
            typ, msg_data = imap.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                logging.warning(f"[{account_email}] Failed to fetch UID {uid_str}")
                continue

            raw_msg = msg_data[0][1]
            msg = BytesParser(policy=policy.default).parsebytes(raw_msg)

            sent_dt = parse_email_date(msg.get("Date"))
            sent_date_iso = sent_dt.astimezone(timezone.utc).isoformat()

            from_email = parseaddr(msg.get("From"))[1] or "unknown"
            to_email = parseaddr(msg.get("To"))[1] or "unknown"
            subject = msg.get("Subject", "")

            # folder logic: attachments/{account_email}/{from or to}/
            if from_email.lower() == account_email.lower():
                folder_party = sanitize_part(to_email)
            else:
                folder_party = sanitize_part(from_email)

            dest_dir = os.path.join(acc_dir, folder_party)
            os.makedirs(dest_dir, exist_ok=True)

            attachment_filenames = []
            any_attachments = False
            any_downloaded = False

            for part in msg.walk():
                if part.is_multipart():
                    continue

                filename = part.get_filename()
                content_disposition = (part.get("Content-Disposition") or "").lower()

                # treat as attachment if filename present or explicit attachment disposition
                if not filename and "attachment" not in content_disposition:
                    continue

                content = part.get_payload(decode=True)
                if not content:
                    continue

                any_attachments = True
                md5 = hashlib.md5(content).hexdigest()

                if md5 in known_hashes:
                    # duplicate across this account; don't store again
                    logging.info(f"[{account_email}] UID {uid_str} attachment {filename} duplicate, skipping save")
                    # we still consider the email as having "downloaded" in metadata
                    continue

                known_hashes.add(md5)
                date_prefix = sent_dt.astimezone(timezone.utc).strftime("%Y%m%d_%H%M")
                base_name = safe_filename(filename or "attachment.bin")
                final_name = f"{date_prefix}_{base_name}"
                full_path = os.path.join(dest_dir, final_name)

                # avoid collision even with same date & time
                counter = 2
                while os.path.exists(full_path):
                    name_no_ext, ext = os.path.splitext(base_name)
                    final_name = f"{date_prefix}_{name_no_ext}_{counter}{ext}"
                    full_path = os.path.join(dest_dir, final_name)
                    counter += 1

                with open(full_path, "wb") as f:
                    f.write(content)

                logging.info(f"[{account_email}] Saved attachment: {full_path}")
                attachment_filenames.append(final_name)
                any_downloaded = True

            # update downloaded_db if there were attachments at all
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

                # merge filenames
                existing_files = [x for x in entry["attachment_filenames"].split(";") if x]
                existing_files.extend(attachment_filenames)
                entry["attachment_filenames"] = ";".join(sorted(set(existing_files)))

                downloaded_db[key] = entry

            # update last_processed_uid regardless, so we don't re-scan
            acc_state["last_processed_uid"] = int(uid_str)
            acc_state["last_processed_date"] = sent_date_iso
            state[account_email] = acc_state

        # save hash index after processing all UIDs
        save_hash_index(known_hashes, hash_idx_path)

    finally:
        if imap is not None:
            try:
                imap.close()
            except Exception:
                pass
            imap.logout()

# ---------- TASK 2: DELETE ATTACHMENTS AFTER RETENTION ----------

def strip_attachments_from_email(raw_msg_bytes, sent_dt: datetime):
    """
    Minimal implementation: keeps all non-attachment parts' text,
    builds a plain text email with a note that attachments were removed.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_msg_bytes)
    text_chunks = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in content_disposition or part.get_filename():
            # skip actual attachments
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
    # copy key headers
    for h in ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To", "References"]:
        if msg.get(h):
            new_msg[h] = msg.get(h)

    new_msg["X-Attachments-Deleted"] = "yes"
    new_msg.set_content(body)

    return new_msg

def delete_old_attachments_for_account(account, state, downloaded_db):
    retention_days = account.get("retention_days", -1)
    if retention_days is None or retention_days < 0:
        # no retention for this account
        return

    account_email = account["email"]
    imap = None
    try:
        imap = connect_imap(account)
        select_all_mail(imap)

        # go through downloaded_db entries for this account
        for (acc, uid), row in list(downloaded_db.items()):
            if acc != account_email:
                continue

            if row.get("attachments_downloaded") != "1":
                continue  # nothing downloaded, skip

            if row.get("attachments_deleted") == "1":
                continue  # already deleted

            sent_date_iso = row.get("sent_date")
            try:
                sent_dt = datetime.fromisoformat(sent_date_iso)
                if sent_dt.tzinfo is None:
                    sent_dt = sent_dt.replace(tzinfo=timezone.utc)
            except Exception:
                sent_dt = datetime.now(timezone.utc)

            age_days = calculate_age_days(sent_dt)
            if age_days < retention_days:
                continue  # not old enough

            uid_bytes = uid.encode()
            logging.info(f"[{account_email}] Stripping attachments for UID {uid} (age {age_days} days)")

            typ, msg_data = imap.uid("FETCH", uid_bytes, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                logging.warning(f"[{account_email}] Failed to fetch UID {uid} for deletion")
                continue

            raw_msg = msg_data[0][1]
            new_msg = strip_attachments_from_email(raw_msg, sent_dt)
            new_bytes = new_msg.as_bytes()

            # append cleaned message to same mailbox
            date_time = imaplib.Time2Internaldate(sent_dt.timetuple())
            typ, _ = imap.append('"[Gmail]/All Mail"', None, date_time, new_bytes)
            if typ != "OK":
                logging.error(f"[{account_email}] Failed to APPEND cleaned message for UID {uid}")
                continue

            # mark original as deleted and expunge
            imap.uid("STORE", uid_bytes, "+FLAGS", r"(\Deleted)")
            imap.expunge()

            # mark as deleted in DB
            row["attachments_deleted"] = "1"
            downloaded_db[(acc, uid)] = row

    finally:
        if imap is not None:
            try:
                imap.close()
            except Exception:
                pass
            imap.logout()

# ---------- MAIN ----------

def main():
    config = load_config()
    state = load_state()
    downloaded_db = load_downloaded_db()

    accounts = config.get("accounts", [])
    if not accounts:
        print("No accounts configured in config.json")
        return

    for account in accounts:
        email_addr = account["email"]
        logging.info(f"--- Processing account {email_addr} (Task 1: download) ---")
        process_new_emails_for_account(account, state, downloaded_db)

    # After downloads, run deletion for those accounts that have retention
    for account in accounts:
        email_addr = account["email"]
        logging.info(f"--- Processing account {email_addr} (Task 2: retention delete) ---")
        delete_old_attachments_for_account(account, state, downloaded_db)

    # Persist state and DB
    save_state(state)
    save_downloaded_db(downloaded_db)

    logging.info("Run completed.")

if __name__ == "__main__":
    main()
