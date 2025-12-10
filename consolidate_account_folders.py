#!/usr/bin/env python3
"""
Account Folder Consolidation Utility

Consolidates duplicate account folders caused by folder naming issues.
Moves files from incorrectly named folders to the correct folder based on config.json
"""

import os
import json
import shutil
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

def sanitize_email_for_folder(email: str) -> str:
    """Sanitize email address for folder name - preserves @ and -"""
    if not email:
        return "unknown"
    email = email.replace(" ", "_")
    email = "".join(c for c in email if c.isalnum() or c in "._-@")
    return email or "unknown"

def get_configured_accounts():
    """Get list of configured email accounts"""
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file not found: {CONFIG_FILE}")
        return []
    
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    
    return [acc['email'] for acc in config.get('accounts', [])]

def find_similar_folders(target_email):
    """Find all folder variations for an email address"""
    # Generate possible variations
    variations = set()
    
    # Without @ and -
    no_special = target_email.replace('@', '').replace('-', '')
    variations.add(no_special)
    
    # With _ instead of @
    underscore = target_email.replace('@', '_')
    variations.add(underscore)
    
    # Without - only
    no_dash = target_email.replace('-', '')
    variations.add(no_dash)
    
    # Without @ only
    no_at = target_email.replace('@', '')
    variations.add(no_at)
    
    # Without @ only
    no_at = target_email.replace('@', '')
    variations.add(no_at)
    
    # The correct one
    correct = sanitize_email_for_folder(target_email)
    
    # Find all matching folders
    matching = []
    if os.path.exists(ATTACHMENTS_ROOT):
        for folder in os.listdir(ATTACHMENTS_ROOT):
            folder_path = os.path.join(ATTACHMENTS_ROOT, folder)
            if os.path.isdir(folder_path):
                if folder in variations and folder != correct:
                    matching.append(folder)
    
    return matching, correct

def merge_folders(source_folder, dest_folder):
    """Merge contents of source folder into destination folder"""
    source_path = os.path.join(ATTACHMENTS_ROOT, source_folder)
    dest_path = os.path.join(ATTACHMENTS_ROOT, dest_folder)
    
    # Create destination if it doesn't exist
    os.makedirs(dest_path, exist_ok=True)
    
    files_moved = 0
    folders_merged = 0
    
    # Walk through source directory
    for root, dirs, files in os.walk(source_path):
        # Calculate relative path from source
        rel_path = os.path.relpath(root, source_path)
        
        # Create corresponding directory in destination
        if rel_path != '.':
            dest_dir = os.path.join(dest_path, rel_path)
            os.makedirs(dest_dir, exist_ok=True)
        else:
            dest_dir = dest_path
        
        # Move all files
        for file in files:
            src_file = os.path.join(root, file)
            dst_file = os.path.join(dest_dir, file)
            
            # Handle duplicates
            if os.path.exists(dst_file):
                # Check if files are identical
                if os.path.getsize(src_file) == os.path.getsize(dst_file):
                    print(f"    Skipping duplicate: {file}")
                    os.remove(src_file)
                else:
                    # Rename with _dup suffix
                    base, ext = os.path.splitext(file)
                    counter = 1
                    while os.path.exists(dst_file):
                        dst_file = os.path.join(dest_dir, f"{base}_dup{counter}{ext}")
                        counter += 1
                    shutil.move(src_file, dst_file)
                    print(f"    Moved (renamed): {file} → {os.path.basename(dst_file)}")
                    files_moved += 1
            else:
                shutil.move(src_file, dst_file)
                files_moved += 1
    
    # Count merged folders
    for root, dirs, files in os.walk(source_path, topdown=False):
        folders_merged += len(dirs)
    
    # Remove empty source directory
    try:
        shutil.rmtree(source_path)
    except Exception as e:
        print(f"    Warning: Could not remove {source_folder}: {e}")
    
    return files_moved, folders_merged

def main():
    print("="*70)
    print("ACCOUNT FOLDER CONSOLIDATION UTILITY")
    print("="*70)
    print("\nThis will consolidate duplicate account folders.")
    print("Files will be moved to the correct folder names.\n")
    
    if not os.path.exists(ATTACHMENTS_ROOT):
        print(f"Attachments folder not found: {ATTACHMENTS_ROOT}")
        return
    
    # Get configured accounts
    accounts = get_configured_accounts()
    if not accounts:
        print("No accounts found in config.json")
        return
    
    print(f"Found {len(accounts)} configured account(s):\n")
    
    total_moved = 0
    total_merged = 0
    
    for email in accounts:
        print(f"Processing: {email}")
        
        # Find similar folders
        similar, correct = find_similar_folders(email)
        
        if not similar:
            correct_path = os.path.join(ATTACHMENTS_ROOT, correct)
            if os.path.exists(correct_path):
                print(f"  ✓ Already using correct folder: {correct}")
            else:
                print(f"  ⊘ No folders found for this account")
            continue
        
        print(f"  Correct folder: {correct}")
        print(f"  Found {len(similar)} duplicate folder(s): {', '.join(similar)}")
        
        # Merge each similar folder
        for source in similar:
            print(f"  → Merging {source} into {correct}...")
            files, folders = merge_folders(source, correct)
            total_moved += files
            total_merged += folders
            print(f"    Moved {files} files, merged {folders} folder(s)")
    
    print(f"\n{'='*70}")
    print("CONSOLIDATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total files moved: {total_moved}")
    print(f"Total folders merged: {total_merged}")
    print(f"{'='*70}\n")
    
    if total_moved > 0:
        print("✓ Consolidation complete! Duplicate folders have been merged.")
    else:
        print("✓ No consolidation needed - folders are already correct.")

if __name__ == "__main__":
    main()
