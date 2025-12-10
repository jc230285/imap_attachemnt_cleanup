#!/usr/bin/env python3
"""
Folder Structure Migration Utility

Migrates existing attachments from the old structure:
  attachments/{account}/user_domain/
  
To the new structure:
  attachments/{account}/domain/user/
"""

import os
import shutil
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")

def extract_email_parts_from_folder(folder_name):
    """
    Extract domain and user from old folder name format.
    Old format: user_domain or user.name_domain.com
    Returns: (domain, user)
    """
    # Try to find the last underscore that separates user from domain
    parts = folder_name.rsplit('_', 1)
    
    if len(parts) == 2:
        user, domain = parts
        return domain, user
    else:
        # Can't parse, keep as-is in unknown folder
        return "unknown", folder_name

def migrate_account_folder(account_path, account_name):
    """Migrate all folders within an account folder"""
    if not os.path.isdir(account_path):
        return 0, 0, 0
    
    print(f"\n{'='*70}")
    print(f"Migrating: {account_name}")
    print(f"{'='*70}")
    
    # Get all immediate subdirectories (old format folders)
    old_folders = [f for f in os.listdir(account_path) 
                   if os.path.isdir(os.path.join(account_path, f))]
    
    folders_migrated = 0
    files_moved = 0
    errors = 0
    
    for old_folder in sorted(old_folders):
        old_path = os.path.join(account_path, old_folder)
        
        # Skip .hashes.json folders or already migrated structure
        if old_folder.startswith('.'):
            continue
        
        # Check if this looks like an already-migrated domain folder
        # (has subdirectories that look like users)
        subfolders = [f for f in os.listdir(old_path) 
                     if os.path.isdir(os.path.join(old_path, f))]
        
        # If it has subfolders, might be already migrated - skip
        if subfolders and not any(f.endswith('.json') or f.endswith('.pdf') or f.endswith('.jpg') 
                                  for f in os.listdir(old_path)):
            print(f"  → Skipping {old_folder} (appears to be already migrated)")
            continue
        
        # Extract domain and user from old folder name
        domain, user = extract_email_parts_from_folder(old_folder)
        
        # Create new path
        new_path = os.path.join(account_path, domain, user)
        
        # If old path and new path are the same, skip
        if os.path.normpath(old_path) == os.path.normpath(new_path):
            print(f"  → Skipping {old_folder} (already in correct location)")
            continue
        
        # Count files in old folder
        try:
            files = [f for f in os.listdir(old_path) 
                    if os.path.isfile(os.path.join(old_path, f))]
            
            if not files:
                print(f"  ⊘ Skipping {old_folder} (empty)")
                continue
            
            # Create new directory structure
            os.makedirs(new_path, exist_ok=True)
            
            # Move all files
            moved_count = 0
            for file in files:
                src = os.path.join(old_path, file)
                dst = os.path.join(new_path, file)
                
                # If destination exists, skip or rename
                if os.path.exists(dst):
                    print(f"    ⚠ File exists at destination, skipping: {file}")
                    continue
                
                shutil.move(src, dst)
                moved_count += 1
            
            # Remove old folder if now empty
            remaining = os.listdir(old_path)
            if not remaining:
                os.rmdir(old_path)
                print(f"  ✓ {old_folder} → {domain}/{user} ({moved_count} files)")
                folders_migrated += 1
            else:
                print(f"  ⚠ {old_folder} → {domain}/{user} ({moved_count} files, {len(remaining)} items remain)")
                folders_migrated += 1
            
            files_moved += moved_count
            
        except Exception as e:
            print(f"  ✗ Error migrating {old_folder}: {e}")
            errors += 1
    
    return folders_migrated, files_moved, errors

def main():
    print("="*70)
    print("FOLDER STRUCTURE MIGRATION UTILITY")
    print("="*70)
    print("\nThis will migrate attachments from old structure:")
    print("  attachments/{account}/user_domain/")
    print("\nTo new structure:")
    print("  attachments/{account}/domain/user/")
    print("\n⚠ WARNING: This will move files. Backup your data first!")
    print("\nPress Ctrl+C to cancel, or Enter to continue...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n\nCancelled.")
        return
    
    if not os.path.exists(ATTACHMENTS_ROOT):
        print(f"\nNo attachments folder found at: {ATTACHMENTS_ROOT}")
        return
    
    # Get all account folders
    account_folders = [f for f in os.listdir(ATTACHMENTS_ROOT) 
                      if os.path.isdir(os.path.join(ATTACHMENTS_ROOT, f))]
    
    if not account_folders:
        print("\nNo account folders found.")
        return
    
    print(f"\nFound {len(account_folders)} account folder(s)")
    
    total_folders = 0
    total_files = 0
    total_errors = 0
    
    for account_folder in sorted(account_folders):
        account_path = os.path.join(ATTACHMENTS_ROOT, account_folder)
        folders, files, errors = migrate_account_folder(account_path, account_folder)
        total_folders += folders
        total_files += files
        total_errors += errors
        
        if folders > 0:
            print(f"  Summary: {folders} folders migrated, {files} files moved")
    
    print(f"\n{'='*70}")
    print("MIGRATION SUMMARY")
    print(f"{'='*70}")
    print(f"Total folders migrated: {total_folders}")
    print(f"Total files moved: {total_files}")
    print(f"Total errors: {total_errors}")
    print(f"{'='*70}\n")
    
    if total_errors == 0:
        print("✓ Migration completed successfully!")
    else:
        print("⚠ Migration completed with some errors. Check the log above.")

if __name__ == "__main__":
    main()
