#!/usr/bin/env python3
"""
Database migration script to update the reset password system
from reset tokens to verification codes.
"""

import sqlite3
import os

def migrate_reset_system():
    """Migrate the database to use verification codes instead of reset tokens"""
    
    if not os.path.exists('oraco_system.db'):
        print("Database file not found. Creating new database...")
        return
    
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    
    try:
        # Check if the new columns already exist
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'reset_code' not in columns:
            print("Adding reset_code column...")
            c.execute('ALTER TABLE users ADD COLUMN reset_code TEXT')
        
        if 'reset_code_expires' not in columns:
            print("Adding reset_code_expires column...")
            c.execute('ALTER TABLE users ADD COLUMN reset_code_expires TIMESTAMP')
        
        if 'reset_code_attempts' not in columns:
            print("Adding reset_code_attempts column...")
            c.execute('ALTER TABLE users ADD COLUMN reset_code_attempts INTEGER DEFAULT 0')
        
        # Remove old columns if they exist
        if 'reset_token' in columns:
            print("Removing old reset_token column...")
            c.execute('ALTER TABLE users DROP COLUMN reset_token')
        
        if 'reset_token_expires' in columns:
            print("Removing old reset_token_expires column...")
            c.execute('ALTER TABLE users DROP COLUMN reset_token_expires')
        
        conn.commit()
        print("✅ Database migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    print("🔄 Starting database migration for reset password system...")
    migrate_reset_system()
    print("✅ Migration script completed!") 