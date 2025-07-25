
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email credentials
EMAIL_ADDRESS = 'oraco.system@gmail.com'
EMAIL_PASSWORD = 'rhlh iokg fkyq fgpi'

def get_file_icon(filename):
    """Get appropriate icon for file type"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    icons = {
        'pdf': 'fa-file-pdf',
        'doc': 'fa-file-word',
        'docx': 'fa-file-word',
        'xls': 'fa-file-excel',
        'xlsx': 'fa-file-excel',
        'txt': 'fa-file-alt',
        'png': 'fa-file-image',
        'jpg': 'fa-file-image',
        'jpeg': 'fa-file-image',
        'gif': 'fa-file-image',
        'zip': 'fa-file-archive',
        'mp4': 'fa-file-video',
        'mp3': 'fa-file-audio'
    }
    return icons.get(ext, 'fa-file')

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_1234567890'

# Make get_file_icon function available to templates
app.jinja_env.globals['get_file_icon'] = get_file_icon

# Configuration
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'mp4', 'mp3'}

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)

def init_db():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
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
        reset_code TEXT,
        reset_code_expires TIMESTAMP,
        reset_code_attempts INTEGER DEFAULT 0
    )''')
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files (
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
    
    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create default admin user if not exists
    c.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    admin_exists = c.fetchone()
    
    if not admin_exists:
        admin_hash = generate_password_hash('admin123')
        c.execute('''INSERT INTO users 
            (username, email, password_hash, full_name, department, role) 
            VALUES (?, ?, ?, ?, ?, ?)''',
            ('admin', 'admin@oraco.co.ke', admin_hash, 'System Administrator', 'IT', 'admin'))
    
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key_from_password(password, salt):
    """Generate encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, password):
    """Encrypt file using AES-256"""
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    
    # Prepend salt to encrypted data
    final_data = salt + encrypted_data
    
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, f"enc_{os.path.basename(file_path)}")
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(final_data)
    
    return encrypted_path, hashlib.sha256(key).hexdigest()

def decrypt_file(encrypted_path, password, output_path):
    """Decrypt file using AES-256"""
    with open(encrypted_path, 'rb') as file:
        file_data = file.read()
    
    # Extract salt and encrypted data
    salt = file_data[:16]
    encrypted_data = file_data[16:]
    
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    
    try:
        decrypted_data = f.decrypt(encrypted_data)
        with open(output_path, 'wb') as output_file:
            output_file.write(decrypted_data)
        return True
    except:
        return False

def log_activity(user_id, action, details=None, ip_address=None):
    """Log user activity"""
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    user_agent = request.headers.get('User-Agent', '')
    c.execute('''INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent) 
                 VALUES (?, ?, ?, ?, ?)''', (user_id, action, details, ip_address, user_agent))
    conn.commit()
    conn.close()

def require_login(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash, role, full_name, last_login FROM users WHERE username = ? AND is_active = 1', 
                 (username,))
        user = c.fetchone()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            session['full_name'] = user[3]
            session['last_login'] = user[4] if user[4] else 'First login'
            
            # Update last login
            c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            
            log_activity(user[0], 'Login', ip_address=request.remote_addr)
            flash('Login successful!', 'success')
            
            if user[2] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
        
        conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'Logout', ip_address=request.remote_addr)
    session.clear()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_login
def dashboard():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    
    # Get user's files and shared files with better information
    c.execute('''SELECT f.id, f.original_filename, f.file_size, f.uploaded_at, f.access_count,
                        u.username as owner_username, f.file_type, f.owner_id, f.shared_with
                 FROM files f 
                 LEFT JOIN users u ON f.owner_id = u.id
                 WHERE f.owner_id = ? OR f.shared_with LIKE ?
                 ORDER BY f.uploaded_at DESC''', 
              (session['user_id'], f'%{session["user_id"]}%'))
    files = c.fetchall()
    
    # Process files to add shared users information
    processed_files = []
    for file in files:
        file_data = list(file)
        shared_users = []
        
        # If this is a shared file, get the usernames of users it's shared with
        if file[8]:  # shared_with field
            shared_user_ids = [uid.strip() for uid in file[8].split(',') if uid.strip()]
            if shared_user_ids:
                placeholders = ','.join(['?' for _ in shared_user_ids])
                c.execute(f'SELECT username FROM users WHERE id IN ({placeholders})', shared_user_ids)
                shared_users = [row[0] for row in c.fetchall()]
        
        # Determine if this is user's own file or shared with them
        is_owned = file[7] == session['user_id']  # owner_id
        file_data.append(is_owned)
        file_data.append(shared_users)
        
        processed_files.append(file_data)
    
    # Get recent activity
    c.execute('''SELECT action, details, timestamp FROM activity_logs 
                 WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10''', 
              (session['user_id'],))
    activities = c.fetchall()
    
    # Get user stats
    c.execute('SELECT COUNT(*) FROM files WHERE owner_id = ?', (session['user_id'],))
    total_files = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM activity_logs WHERE user_id = ? AND DATE(timestamp) = DATE("now")', 
              (session['user_id'],))
    today_activities = c.fetchone()[0]
    
    conn.close()
    last_login = session.get('last_login', 'N/A')
    return render_template('dashboard.html', files=processed_files, activities=activities, 
                         last_login=last_login, total_files=total_files, 
                         today_activities=today_activities)

@app.route('/admin')
@require_admin
def admin_dashboard():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM files')
    total_files = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM activity_logs WHERE DATE(timestamp) = DATE("now")')
    today_activities = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM users WHERE DATE(last_login) = DATE("now")')
    today_logins = c.fetchone()[0]
    
    # Get recent files
    c.execute('''SELECT f.original_filename, u.username, f.uploaded_at, f.file_size, f.file_type
                 FROM files f 
                 JOIN users u ON f.owner_id = u.id 
                 ORDER BY f.uploaded_at DESC LIMIT 10''')
    recent_files = c.fetchall()
    
    # Get recent activities
    c.execute('''SELECT u.username, a.action, a.details, a.timestamp, a.ip_address
                 FROM activity_logs a 
                 JOIN users u ON a.user_id = u.id 
                 ORDER BY a.timestamp DESC LIMIT 15''')
    recent_activities = c.fetchall()
    
    # Get user login stats
    c.execute('''SELECT id, username, last_login, is_active 
                 FROM users 
                 ORDER BY last_login DESC NULLS LAST''')
    user_logins = c.fetchall()
    
    conn.close()
    return render_template('admin_dashboard.html', 
                         total_users=total_users, 
                         total_files=total_files,
                         today_activities=today_activities,
                         today_logins=today_logins,
                         recent_files=recent_files,
                         recent_activities=recent_activities,
                         user_logins=user_logins)

@app.route('/upload', methods=['GET', 'POST'])
@require_login
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        password = request.form['password']
        shared_with = request.form.getlist('shared_with')
        
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Get file type
            file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
            
            # Encrypt the file
            encrypted_path, key_hash = encrypt_file(file_path, password)
            file_size = os.path.getsize(file_path)
            
            # Save to database
            conn = sqlite3.connect('oraco_system.db')
            c = conn.cursor()
            c.execute('''INSERT INTO files 
                        (original_filename, encrypted_filename, file_size, owner_id, 
                         shared_with, encryption_key_hash, file_type) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (filename, os.path.basename(encrypted_path), file_size, 
                      session['user_id'], ','.join(shared_with), key_hash, file_type))
            conn.commit()
            conn.close()
            
            # Clean up original file
            os.remove(file_path)
            
            log_activity(session['user_id'], 'File Upload', 
                        f'Uploaded: {filename}', request.remote_addr)
            flash('File encrypted and uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type!', 'error')
    
    # Get list of users for sharing
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('SELECT id, username, full_name, department FROM users WHERE is_active = 1 AND id != ?', 
             (session['user_id'],))
    users = c.fetchall()
    conn.close()
    
    return render_template('upload.html', users=users)

@app.route('/download/<int:file_id>')
@require_login
def download_file(file_id):
    password = request.args.get('password')
    if not password:
        flash('Password required for decryption!', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT original_filename, encrypted_filename, owner_id, shared_with 
                 FROM files WHERE id = ?''', (file_id,))
    file_data = c.fetchone()
    
    if not file_data:
        flash('File not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if user has access
    owner_id, shared_with = file_data[2], file_data[3]
    if owner_id != session['user_id'] and str(session['user_id']) not in shared_with:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard'))
    
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, file_data[1])
    output_path = os.path.join(UPLOAD_FOLDER, f"temp_{file_data[0]}")
    
    if decrypt_file(encrypted_path, password, output_path):
        # Update access count
        c.execute('''UPDATE files SET access_count = access_count + 1, 
                     last_accessed = CURRENT_TIMESTAMP WHERE id = ?''', (file_id,))
        conn.commit()
        
        log_activity(session['user_id'], 'File Download', 
                    f'Downloaded: {file_data[0]}', request.remote_addr)
        
        conn.close()
        return send_file(output_path, as_attachment=True, 
                        download_name=file_data[0])
    else:
        flash('Incorrect password or corrupted file!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/manage_users')
@require_admin
def manage_users():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT id, username, email, full_name, department, role, 
                        is_active, created_at, last_login 
                 FROM users ORDER BY created_at DESC''')
    users = c.fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@require_admin
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        department = request.form['department']
        role = request.form['role']
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('oraco_system.db')
            c = conn.cursor()
            c.execute('''INSERT INTO users 
                        (username, email, password_hash, full_name, department, role) 
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, email, password_hash, full_name, department, role))
            conn.commit()
            conn.close()
            
            log_activity(session['user_id'], 'User Registration', 
                        f'Added user: {username}', request.remote_addr)
            flash('User added successfully!', 'success')
            return redirect(url_for('manage_users'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
    
    return render_template('add_user.html')

@app.route('/toggle_user/<int:user_id>')
@require_admin
def toggle_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot deactivate yourself!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('SELECT username, is_active FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if user:
        new_status = 0 if user[1] else 1
        c.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        
        action = 'deactivated' if new_status == 0 else 'activated'
        log_activity(session['user_id'], f'User {action}', 
                    f'{action.capitalize()} user: {user[0]}', request.remote_addr)
        flash(f'User {user[0]} {action} successfully!', 'success')
    
    conn.close()
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@require_admin
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete yourself!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if user:
        # Delete user's files
        c.execute('DELETE FROM files WHERE owner_id = ?', (user_id,))
        # Delete user's activity logs
        c.execute('DELETE FROM activity_logs WHERE user_id = ?', (user_id,))
        # Delete user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        log_activity(session['user_id'], 'User Deleted', 
                    f'Deleted user: {user[0]}', request.remote_addr)
        flash(f'User {user[0]} deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('manage_users'))

@app.route('/system_logs')
@require_admin
def system_logs():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT u.username, a.action, a.details, a.ip_address, a.timestamp, a.user_agent
                 FROM activity_logs a 
                 JOIN users u ON a.user_id = u.id 
                 ORDER BY a.timestamp DESC LIMIT 100''')
    logs = c.fetchall()
    conn.close()
    return render_template('system_logs.html', logs=logs)

@app.route('/file_management')
@require_admin
def file_management():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT f.id, f.original_filename, f.file_size, f.uploaded_at, f.access_count,
                        u.username as owner, f.file_type, f.shared_with
                 FROM files f 
                 JOIN users u ON f.owner_id = u.id 
                 ORDER BY f.uploaded_at DESC''')
    files = c.fetchall()
    
    # Get user information for shared files
    shared_files_info = []
    for file in files:
        shared_with = file[7] if file[7] else ''
        shared_users = []
        if shared_with:
            user_ids = [uid.strip() for uid in shared_with.split(',') if uid.strip()]
            if user_ids:
                placeholders = ','.join(['?' for _ in user_ids])
                c.execute(f'SELECT username FROM users WHERE id IN ({placeholders})', user_ids)
                shared_usernames = [row[0] for row in c.fetchall()]
                shared_users = shared_usernames
        
        shared_files_info.append({
            'file_data': file,
            'shared_users': shared_users
        })
    
    conn.close()
    return render_template('file_management.html', files=files, shared_files_info=shared_files_info)

@app.route('/admin_download/<int:file_id>')
@require_admin
def admin_download_file(file_id):
    """Admin download route for security monitoring"""
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT original_filename, encrypted_filename, owner_id 
                 FROM files WHERE id = ?''', (file_id,))
    file_data = c.fetchone()
    
    if not file_data:
        flash('File not found!', 'error')
        return redirect(url_for('file_management'))
    
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, file_data[1])
    output_path = os.path.join(UPLOAD_FOLDER, f"admin_temp_{file_data[0]}")
    
    # For admin downloads, we'll create a temporary decrypted version
    # Note: This is for security monitoring only - in production, you might want additional safeguards
    
    # Get the encryption key hash to attempt decryption
    c.execute('SELECT encryption_key_hash FROM files WHERE id = ?', (file_id,))
    key_hash = c.fetchone()[0]
    
    # Log admin download attempt
    log_activity(session['user_id'], 'Admin File Access', 
                f'Admin accessed file: {file_data[0]}', request.remote_addr)
    
    conn.close()
    
    # For now, we'll redirect to the regular download with a note
    flash('Admin access: Please use the regular download with the file password for decryption.', 'info')
    return redirect(url_for('file_management'))

@app.route('/delete_file/<int:file_id>')
@require_admin
def delete_file(file_id):
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('SELECT original_filename, encrypted_filename FROM files WHERE id = ?', (file_id,))
    file_data = c.fetchone()
    
    if file_data:
        # Delete encrypted file
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, file_data[1])
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        # Delete from database
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        
        log_activity(session['user_id'], 'File Deleted', 
                    f'Deleted file: {file_data[0]}', request.remote_addr)
        flash(f'File {file_data[0]} deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('file_management'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user:
            session['reset_email'] = email
            
            success = generate_and_send_reset_email(email)
            if success:
                flash('Verification code sent to your email! Please check your inbox.', 'success')
                return redirect(url_for('verify_code'))
            else:
                flash('Failed to send verification code. Please try again.', 'error')
        else:
            flash('Email not found!', 'error')
        
        conn.close()
    
    return render_template('reset_password.html')

def generate_and_send_reset_email(email):
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()

    # Check user exists
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    if not user:
        conn.close()
        return False

    user_id = user[0]
    # Generate a 6-digit verification code
    reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expires = datetime.now() + timedelta(minutes=15)  # 15 minutes expiry

    # Save code and expiry to DB
    c.execute('''UPDATE users SET reset_code = ?, reset_code_expires = ?, reset_code_attempts = 0 WHERE id = ?''',
              (reset_code, expires, user_id))
    conn.commit()
    conn.close()

    # Prepare email content
    sender_email = EMAIL_ADDRESS
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = 'Oraco Kenya - Password Reset Verification Code'

    body = f"""Hello,

You have requested to reset your password for your Oraco Kenya Secure File Encryption account.

Your verification code is: {reset_code}

This code will expire in 15 minutes for security reasons.

If you did not request this password reset, please ignore this email.

Best regards,
Oraco Kenya Security Team"""
    
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email sending failed:", e)
        return False

@app.route('/resend_reset_email', methods=['GET'])
def resend_reset_email():
    email = session.get('reset_email')
    if not email:
        flash("No email to resend code to. Please initiate password reset again.", "error")
        return redirect(url_for('reset_password'))

    success = generate_and_send_reset_email(email)
    if success:
        flash("Verification code resent! Please check your inbox.", "success")
    else:
        flash("Failed to resend verification code.", "error")
    return redirect(url_for('verify_code'))

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        code = request.form['code']
        email = session.get('reset_email')

        if not email:
            flash("No email to verify code for. Please initiate password reset again.", "error")
            return redirect(url_for('reset_password'))

        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        c.execute('SELECT id, reset_code, reset_code_expires FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user:
            conn.close()
            flash("User not found for this email. Please try again.", "error")
            return redirect(url_for('reset_password'))

        user_id, stored_code, token_expiry = user

        # Check if code is expired
        try:
            expiry_time = datetime.strptime(token_expiry, "%Y-%m-%d %H:%M:%S.%f")
        except:
            expiry_time = datetime.strptime(token_expiry, "%Y-%m-%d %H:%M:%S")

        if datetime.now() > expiry_time:
            conn.close()
            flash("Verification code has expired. Please request a new one.", "warning")
            return redirect(url_for('reset_password'))

        if code == stored_code:
            # Store the verified code in session for the password reset form
            session['verified_code'] = stored_code
            flash("Verification successful! Please enter your new password.", "success")
            return redirect(url_for('reset_password_form'))
        else:
            # Increment failed attempts
            c.execute('UPDATE users SET reset_code_attempts = reset_code_attempts + 1 WHERE id = ?', (user_id,))
            conn.commit()
            
            # Check if too many attempts
            c.execute('SELECT reset_code_attempts FROM users WHERE id = ?', (user_id,))
            attempts = c.fetchone()[0]
            if attempts >= 3:
                flash("Too many failed attempts. Please request a new verification code.", "error")
                return redirect(url_for('reset_password'))
            
            flash("Incorrect verification code. Please try again.", "error")
        
        conn.close()

    return render_template('verify_code.html')

@app.route('/reset_password_form', methods=['GET', 'POST'])
def reset_password_form():
    verified_code = session.get('verified_code')
    email = session.get('reset_email')
    
    if not verified_code or not email:
        flash("Please complete the verification process first.", "error")
        return redirect(url_for('reset_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('reset_form.html')

        if len(new_password) < 6:
            flash("Password must be at least 6 characters long!", "error")
            return render_template('reset_form.html')

        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        
        # Verify the code again for security
        c.execute('SELECT id, reset_code FROM users WHERE email = ? AND reset_code = ?', (email, verified_code))
        user = c.fetchone()
        
        if not user:
            conn.close()
            flash("Verification code is invalid. Please start over.", "error")
            session.pop('verified_code', None)
            session.pop('reset_email', None)
            return redirect(url_for('reset_password'))

        user_id = user[0]
        password_hash = generate_password_hash(new_password)

        # Update password and clear reset data
        c.execute('''UPDATE users SET password_hash = ?, reset_code = NULL, reset_code_expires = NULL, reset_code_attempts = 0 WHERE id = ?''', 
                 (password_hash, user_id))
        conn.commit()
        conn.close()

        # Clear session data
        session.pop('verified_code', None)
        session.pop('reset_email', None)

        flash("Your password has been reset successfully. You can now login with your new password.", "success")
        return redirect(url_for('login'))

    return render_template('reset_form.html')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
