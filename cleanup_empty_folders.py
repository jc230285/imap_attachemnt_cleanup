#!/usr/bin/env python3
"""
Empty Folder Cleanup Utility

Removes empty folders from the attachments directory.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")

def remove_empty_folders(path):
    """Recursively remove empty folders"""
    if not os.path.isdir(path):
        return False
    
    # First, try to remove empty subfolders
    all_subdirs = [os.path.join(path, d) for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
    
    for subdir in all_subdirs:
        remove_empty_folders(subdir)
    
    # Check if this folder is now empty (after removing empty subdirs)
    remaining = os.listdir(path)
    
    # Filter out .hashes.json as it doesn't count as "content"
    actual_content = [item for item in remaining if item != '.hashes.json']
    
    if len(actual_content) == 0:
        try:
            # If only .hashes.json exists, remove it first
            if '.hashes.json' in remaining:
                os.remove(os.path.join(path, '.hashes.json'))
            
            os.rmdir(path)
            return True
        except Exception as e:
            print(f"  ⚠ Could not remove {path}: {e}")
            return False
    
    return False

def main():
    print("="*70)
    print("EMPTY FOLDER CLEANUP UTILITY")
    print("="*70)
    print("\nThis will remove all empty folders from the attachments directory.")
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
    print()
    
    total_removed = 0
    
    for account_folder in sorted(account_folders):
        account_path = os.path.join(ATTACHMENTS_ROOT, account_folder)
        print(f"Processing: {account_folder}")
        
        # Get all subfolders
        subfolders = [os.path.join(account_path, d) for d in os.listdir(account_path) 
                     if os.path.isdir(os.path.join(account_path, d))]
        
        removed_count = 0
        for subfolder in sorted(subfolders):
            subfolder_name = os.path.basename(subfolder)
            if remove_empty_folders(subfolder):
                print(f"  ✗ Removed empty folder: {subfolder_name}")
                removed_count += 1
        
        if removed_count == 0:
            print(f"  ✓ No empty folders found")
        else:
            print(f"  Removed {removed_count} empty folder(s)")
        
        total_removed += removed_count
    
    print(f"\n{'='*70}")
    print(f"Total empty folders removed: {total_removed}")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
