#!/usr/bin/env python3
"""
Duplicate Attachment Cleanup Utility

This script identifies and removes duplicate attachments based on MD5 hash.
It will:
1. Scan all attachments in each account folder
2. Calculate MD5 hash for each file
3. Keep the first occurrence, delete duplicates
4. Update the .hashes.json file with the correct unique hashes
"""

import os
import json
import hashlib
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACHMENTS_ROOT = os.path.join(BASE_DIR, "attachments")

def calculate_file_hash(filepath):
    """Calculate MD5 hash of a file"""
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
    return md5.hexdigest()

def clean_duplicates_for_account(account_folder):
    """Remove duplicate files in an account folder"""
    account_path = os.path.join(ATTACHMENTS_ROOT, account_folder)
    
    if not os.path.isdir(account_path):
        return
    
    print(f"\n{'='*70}")
    print(f"Processing: {account_folder}")
    print(f"{'='*70}")
    
    hash_to_files = defaultdict(list)
    total_files = 0
    total_size = 0
    
    # Scan all files and group by hash
    for root, dirs, files in os.walk(account_path):
        for filename in files:
            if filename == '.hashes.json':
                continue
                
            filepath = os.path.join(root, filename)
            filesize = os.path.getsize(filepath)
            total_files += 1
            total_size += filesize
            
            try:
                file_hash = calculate_file_hash(filepath)
                hash_to_files[file_hash].append({
                    'path': filepath,
                    'name': filename,
                    'size': filesize,
                    'relative': os.path.relpath(filepath, account_path)
                })
            except Exception as e:
                print(f"  ⚠ Error processing {filename}: {e}")
    
    # Identify and remove duplicates
    duplicates_found = 0
    duplicates_removed = 0
    space_freed = 0
    unique_hashes = set()
    
    for file_hash, file_list in hash_to_files.items():
        unique_hashes.add(file_hash)
        
        if len(file_list) > 1:
            duplicates_found += len(file_list) - 1
            
            # Keep the first one, delete the rest
            keeper = file_list[0]
            print(f"\n  Hash: {file_hash[:16]}... ({len(file_list)} copies)")
            print(f"    ✓ KEEPING: {keeper['relative']}")
            
            for duplicate in file_list[1:]:
                try:
                    print(f"    ✗ DELETING: {duplicate['relative']}")
                    os.remove(duplicate['path'])
                    duplicates_removed += 1
                    space_freed += duplicate['size']
                except Exception as e:
                    print(f"      ERROR: Could not delete - {e}")
    
    # Update the .hashes.json file
    hash_file = os.path.join(account_path, '.hashes.json')
    with open(hash_file, 'w') as f:
        json.dump(list(unique_hashes), f, indent=2)
    
    print(f"\n  Summary:")
    print(f"    Total files scanned: {total_files}")
    print(f"    Unique files: {len(hash_to_files)}")
    print(f"    Duplicates found: {duplicates_found}")
    print(f"    Duplicates removed: {duplicates_removed}")
    print(f"    Space freed: {space_freed / 1024 / 1024:.2f} MB")
    print(f"    Hash index updated: {len(unique_hashes)} unique hashes")
    
    return {
        'account': account_folder,
        'total_files': total_files,
        'unique_files': len(hash_to_files),
        'duplicates_removed': duplicates_removed,
        'space_freed': space_freed
    }

def main():
    print("="*70)
    print("DUPLICATE ATTACHMENT CLEANUP UTILITY")
    print("="*70)
    print("\nThis will scan for and remove duplicate attachments.")
    print("The first occurrence of each file will be kept.")
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
    
    # Process each account
    results = []
    for account_folder in sorted(account_folders):
        result = clean_duplicates_for_account(account_folder)
        if result:
            results.append(result)
    
    # Overall summary
    print(f"\n\n{'='*70}")
    print("OVERALL SUMMARY")
    print(f"{'='*70}")
    
    total_removed = sum(r['duplicates_removed'] for r in results)
    total_space_freed = sum(r['space_freed'] for r in results)
    
    print(f"Accounts processed: {len(results)}")
    print(f"Total duplicates removed: {total_removed}")
    print(f"Total space freed: {total_space_freed / 1024 / 1024:.2f} MB")
    print(f"\n{'='*70}")
    print("Cleanup complete!")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
