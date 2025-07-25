#!/usr/bin/env python3
"""
Database Reset Script for ORACO Secure File System
This script will reset the database and create a fresh admin user.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash

def reset_database():
    """Reset the database and create fresh admin user"""
    
    # Remove existing database
    if os.path.exists('oraco_system.db'):
        os.remove('oraco_system.db')
        print("✓ Removed existing database")
    
    # Create new database
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        department TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        reset_token TEXT,
        reset_token_expires TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        shared_with TEXT,
        encryption_key_hash TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed TIMESTAMP,
        access_count INTEGER DEFAULT 0,
        file_type TEXT,
        FOREIGN KEY (owner_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create admin user
    admin_hash = generate_password_hash('admin123')
    c.execute('''INSERT INTO users 
        (username, email, password_hash, full_name, department, role) 
        VALUES (?, ?, ?, ?, ?, ?)''',
        ('admin', 'admin@oraco.co.ke', admin_hash, 'System Administrator', 'IT', 'admin'))
    
    conn.commit()
    conn.close()
    
    print("✓ Database created successfully")
    print("✓ Admin user created")
    print("\n📋 Admin Login Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   Email: admin@oraco.co.ke")
    print("\n🚀 You can now run the application with: python app.py")

if __name__ == '__main__':
    print("🔄 Resetting ORACO Secure File System Database...")
    reset_database()
    print("\n✅ Database reset completed successfully!") 