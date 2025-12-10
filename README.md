# IMAP Attachment Cleanup Tool

A Python tool to automatically download and manage email attachments from IMAP mailboxes with concurrent processing, failure tracking, and a real-time GUI progress window.

## Features

### 🚀 **Concurrent Processing**
- Processes multiple mailboxes simultaneously using ThreadPoolExecutor
- Configurable worker threads (default: up to 3 concurrent connections)
- Significantly faster than sequential processing

### 📊 **Real-Time GUI Progress Window**
- Live progress bar showing completion percentage
- Activity log with color-coded messages (success/error/warning)
- Real-time statistics (accounts processed, messages scanned, attachments saved)
- Non-blocking interface - watch the process as it runs

### 🛡️ **Failure Tracking & Recovery**
- Records last successful run and last failure for each account
- Automatically skips accounts that previously failed
- Detailed error logging in `failures.json`
- If any mailbox fails, it stops processing that specific mailbox while continuing with others

### 📁 **Smart Attachment Management**
- Downloads attachments with deduplication (MD5 hash-based)
- Organizes by account and sender/recipient
- Tracks all downloads in CSV database
- Optional retention-based deletion of old attachments

## Installation

1. Clone this repository:
```bash
git clone https://github.com/jc230285/imap_attachemnt_cleanup.git
cd imap_attachemnt_cleanup
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the template configuration:
```bash
cp config.template.json config.json
```

2. Edit `config.json` with your email accounts:
```json
{
  "accounts": [
    {
      "email": "your-email@example.com",
      "imap_host": "imap.gmail.com",
      "username": "your-email@example.com",
      "password": "YOUR_APP_PASSWORD_HERE",
      "retention_days": 700
    }
  ]
}
```

### Gmail Setup
For Gmail accounts, you need to:
1. Enable 2-factor authentication
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the App Password in the config (not your regular password)

### Retention Settings
- `retention_days: 700` - Delete attachments older than 700 days
- `retention_days: -1` - Never delete attachments (archive only)

## Usage

Run the script:
```bash
python mailbox_cleaner.py
```

The GUI window will open showing:
- Progress bar with percentage completion
- Real-time activity log
- Statistics (accounts, messages, attachments)
- Color-coded status messages

## Output Files

- `attachments/` - Downloaded attachments organized by account and sender
- `state.json` - Last processed UID for each account (resume capability)
- `downloaded.csv` - Database of all processed messages
- `failures.json` - Failure tracking for each account
- `logs/mail_cleaner.log` - Detailed execution log

## Failure Recovery

The tool tracks failures in `failures.json`:
```json
{
  "email@example.com": {
    "last_success": "2025-12-10T10:30:00Z",
    "last_failure": "2025-12-10T11:00:00Z",
    "last_error": "Authentication failed",
    "error_message": "IMAP4.error: LOGIN failed"
  }
}
```

If an account has a recorded failure, it will be skipped on the next run. To retry:
1. Fix the issue (password, permissions, etc.)
2. Delete that account's entry from `failures.json`
3. Run the script again

## File Organization

Attachments are saved to:
```
attachments/
  ├── your_email_example_com/
  │   ├── sender1_email_com/
  │   │   ├── 20251210_1430_document.pdf
  │   │   └── 20251210_1530_image.jpg
  │   └── sender2_email_com/
  │       └── 20251209_0900_spreadsheet.xlsx
```

## Concurrent Processing

The tool uses thread-based concurrency:
- **Default**: Up to 3 concurrent IMAP connections
- **Safe**: Each account has its own IMAP connection
- **Efficient**: Processes multiple mailboxes simultaneously
- **Configurable**: Adjust `max_workers` in `main()` function

## Security Notes

⚠️ **Important**: 
- Never commit `config.json` to git (it contains passwords)
- Use app-specific passwords, not your main email password
- The `.gitignore` file protects sensitive data from being committed

## Troubleshooting

### "Skipping account - previous failure"
Check `failures.json` and fix the error, then remove that account's entry to retry.

### GUI not appearing
Ensure tkinter is installed (comes with Python on Windows, may need installation on Linux):
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk
```

### IMAP connection errors
- Verify IMAP is enabled in your email provider settings
- Check your app password is correct
- Ensure firewall isn't blocking IMAP port (993)

## License

MIT License - See LICENSE file for details

## Author

jc230285
