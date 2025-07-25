
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
EMAIL_PASSWORD = 'rhlh iokg fkyq fgpi'  # Use an App Password if using Gmail


app = Flask(__name__)
app.secret_key = 'your_super_secret_key_1234567890'


# Configuration
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

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
        reset_token TEXT,
        reset_token_expires TIMESTAMP
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
        FOREIGN KEY (owner_id) REFERENCES users (id)
    )''')
    
    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Create default admin user
    admin_hash = generate_password_hash('oraco_@12345')
    c.execute('''INSERT OR IGNORE INTO users 
        (username, email, password_hash, full_name, department, role) 
        VALUES (?, ?, ?, ?, ?, ?)''',
        ('Oraco Kenya', 'admin@oraco.co.ke', admin_hash, 'System Administrator', 'IT', 'admin'))
    
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
    c.execute('''INSERT INTO activity_logs (user_id, action, details, ip_address) 
                 VALUES (?, ?, ?, ?)''', (user_id, action, details, ip_address))
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
        c.execute('SELECT id, password_hash, role, full_name FROM users WHERE username = ? AND is_active = 1', 
                 (username,))
        user = c.fetchone()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            session['full_name'] = user[3]
            
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
    
    # Get user's files
    c.execute('''SELECT f.id, f.original_filename, f.file_size, f.uploaded_at, f.access_count,
                        u.username as shared_by
                 FROM files f 
                 LEFT JOIN users u ON f.owner_id = u.id
                 WHERE f.owner_id = ? OR f.shared_with LIKE ?
                 ORDER BY f.uploaded_at DESC''', 
              (session['user_id'], f'%{session["user_id"]}%'))
    files = c.fetchall()
    
    # Get recent activity
    c.execute('''SELECT action, details, timestamp FROM activity_logs 
                 WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10''', 
              (session['user_id'],))
    activities = c.fetchall()
    
    conn.close()
    return render_template('dashboard.html', files=files, activities=activities)

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
    
    # Get recent files
    c.execute('''SELECT f.original_filename, u.username, f.uploaded_at, f.file_size
                 FROM files f 
                 JOIN users u ON f.owner_id = u.id 
                 ORDER BY f.uploaded_at DESC LIMIT 10''')
    recent_files = c.fetchall()
    
    # Get recent activities
    c.execute('''SELECT u.username, a.action, a.details, a.timestamp
                 FROM activity_logs a 
                 JOIN users u ON a.user_id = u.id 
                 ORDER BY a.timestamp DESC LIMIT 15''')
    recent_activities = c.fetchall()
    
    conn.close()
    return render_template('admin_dashboard.html', 
                         total_users=total_users, 
                         total_files=total_files,
                         today_activities=today_activities,
                         recent_files=recent_files,
                         recent_activities=recent_activities)

@app.route('/upload', methods=['GET', 'POST'])
@require_login
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        password = request.form['password']
        shared_with = request.form.get('shared_with', '')
        
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Encrypt the file
            encrypted_path, key_hash = encrypt_file(file_path, password)
            file_size = os.path.getsize(file_path)
            
            # Save to database
            conn = sqlite3.connect('oraco_system.db')
            c = conn.cursor()
            c.execute('''INSERT INTO files 
                        (original_filename, encrypted_filename, file_size, owner_id, 
                         shared_with, encryption_key_hash) 
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (filename, os.path.basename(encrypted_path), file_size, 
                      session['user_id'], shared_with, key_hash))
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
    c.execute('SELECT id, username, full_name FROM users WHERE is_active = 1 AND id != ?', 
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

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = sqlite3.connect('oraco_system.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user:
            reset_token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(hours=1)
            session['last_reset_email'] = email 

            c.execute('''UPDATE users SET reset_token = ?, reset_token_expires = ? 
                        WHERE email = ?''', (reset_token, expires, email))
            conn.commit()
            
            # In a real application, send email here
            flash(f'Password reset token: {reset_token} (expires in 1 hour)', 'info')
        else:
            flash('Email not found!', 'error')
        
        conn.close()
    
    return render_template('reset_password.html')
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('SELECT id, reset_token_expires FROM users WHERE reset_token = ?', (token,))
    user = c.fetchone()

    if not user:
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('reset_password'))

    expires = datetime.strptime(user[1], '%Y-%m-%d %H:%M:%S.%f')
    if datetime.now() > expires:
        flash('Reset token has expired', 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        # Hash your password here before storing it!
        c.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', (new_password, user[0]))
        conn.commit()
        flash('Password reset successful! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_with_token.html', token=token)

@app.route('/resend_reset_email', methods=['GET'])
def resend_reset_email():
    if 'last_reset_email' not in session:
        flash('No email to resend link to. Please initiate password reset again.', 'error')
        return redirect(url_for('reset_password'))

    email = session['last_reset_email']

    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()

    c.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = c.fetchone()

    if user:
        # ✅ Generate token
        token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(hours=1)

        # ✅ Save to DB
        c.execute('''UPDATE users SET reset_token = ?, reset_token_expires = ?
                     WHERE email = ?''', (token, expires, email))
        conn.commit()

        # ✅ Build reset link (use ngrok or local IP depending on your setup)
        reset_link = f"https://YOUR_NGROK_SUBDOMAIN.ngrok-free.app/reset/{token}"
        body = f"Click the link to reset your password (valid for 1 hour):\n\n{reset_link}"

        # ✅ Email sending
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email
        msg['Subject'] = "Resend Password Reset Link"
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
            server.quit()
            flash('Password reset link resent successfully!', 'success')
        except Exception as e:
            flash(f'Failed to resend email: {str(e)}', 'error')
    else:
        flash('Email not found!', 'error')

    conn.close()
    return redirect(url_for('reset_password'))


def send_password_reset_email(email, token):
    sender_email = 'oraco.system@gmail.com'
    receiver_email = email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = '🔐 ORACO Password Reset'

    ngrok_url= "https://40ec48e78479.ngrok-free.app"
    reset_link=f"{ngrok_url}/reset/{token}" #use "token" instead of "reset_token" if you want to use the token variable directly

    body = f"Click the link below to reset your password (valid for 1 hour):\n\n{reset_link}"
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, 'your_app_password_here')  # Use your app password here
    server.send_message(msg)
    server.quit()


    if user:
        reset_token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(hours=1)

        c.execute('''UPDATE users SET reset_token = ?, reset_token_expires = ? 
                     WHERE email = ?''', (reset_token, expires, email))
        conn.commit()
        conn.close()

        send_password_reset_email(email, reset_token)

        flash('Password reset email resent. Please check your inbox.', 'info')
    else:
        conn.close()
        flash('Email not found!', 'error')

    return redirect(url_for('reset_password'))


    # Step 4: Send email
    try:
        sender_email = 'oraco.system@gmail.com'
        receiver_email = email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = '🔁 Resent ORACO Password Reset Link'

        reset_link = f"http://127.0.0.1:5000/reset/{reset_token}"
        body = f"Click the link below to reset your password (valid for 1 hour):\n\n{reset_link}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, 'rhlh iokg fkyq fgpi')  # Your app password
        server.send_message(msg)
        server.quit()

        flash("✅ Reset link resent to your email.", "success")

    except Exception as e:
        flash(f"❌ Failed to resend email: {str(e)}", "danger")

    return redirect(url_for('reset_password'))

@app.route('/system_logs')
@require_admin
def system_logs():
    conn = sqlite3.connect('oraco_system.db')
    c = conn.cursor()
    c.execute('''SELECT u.username, a.action, a.details, a.ip_address, a.timestamp
                 FROM activity_logs a 
                 JOIN users u ON a.user_id = u.id 
                 ORDER BY a.timestamp DESC LIMIT 100''')
    logs = c.fetchall()
    conn.close()
    return render_template('system_logs.html', logs=logs)

@app.route('/send-test-email')
@require_admin
def send_test_email():
    try:
        sender_email = 'oraco.system@gmail.com'  # Use your own admin email
        receiver_email = 'ochiengdp@gmail.com'  # Change to your real test email

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = '🔐 ORACO System Email Test'

        body = 'This is a test email sent securely from the ORACO Secure File System.'
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, 'rhlh iokg fkyq fgpi')  # Use app password, not your real Gmail password
        server.send_message(msg)
        server.quit()

        flash("✅ Email sent successfully!", "success")
    except Exception as e:
        flash(f"❌ Failed to send email: {str(e)}", "danger")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
