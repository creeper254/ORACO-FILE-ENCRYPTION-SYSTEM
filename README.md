
# Oraco Kenya SecureFiles - Complete File Encryption System

A secure file encryption and decryption system built with Flask, featuring AES-256 encryption, user management, and comprehensive logging.

## 🔐 Features

- **AES-256 Encryption**: Military-grade file encryption using PBKDF2 key derivation
- **User Management**: Admin interface for managing users and permissions
- **File Sharing**: Secure file sharing between organization members
- **Activity Logging**: Comprehensive audit trail of all system activities
- **Password Reset**: Secure password reset functionality
- **Admin Dashboard**: Real-time statistics and system monitoring
- **Role-based Access**: Admin and user role separation

## 📁 Project Structure

```
oraco-kenya-securefiles/
├── main.py                 # Main Flask application
├── oraco_system.db         # SQLite database (auto-created)
├── pyproject.toml          # Python dependencies
├── .replit                 # Replit configuration
├── README.md               # This file
├── templates/              # HTML templates
│   ├── base.html          # Base template
│   ├── login.html         # Login page
│   ├── dashboard.html     # User dashboard
│   ├── admin_dashboard.html # Admin dashboard
│   ├── upload.html        # File upload page
│   ├── manage_users.html  # User management
│   ├── add_user.html      # Add new user
│   ├── reset_password.html # Password reset
│   └── system_logs.html   # System activity logs
├── static/css/
│   └── style.css          # Application styles
├── uploads/               # Temporary file storage
└── encrypted_files/       # Encrypted file storage
```

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Flask 3.1.1+
- Cryptography 45.0.5+
- Werkzeug 3.1.3+

### Installation & Setup

1. **Clone/Download the project**
   ```bash
   # All files are already in your current directory
   ```

2. **Install Dependencies**
   ```bash
   pip install flask cryptography werkzeug
   ```

3. **Run the Application**
   ```bash
   python main.py
   ```

4. **Access the System**
   - Open your browser to `http://localhost:5000`
   - Default admin credentials:
     - Username: `admin`
     - Password: `admin123`

## 👥 User Roles

### Admin Users
- Access to admin dashboard
- User management (add, view, manage users)
- System logs monitoring
- File oversight across organization
- System statistics and monitoring

### Regular Users
- File encryption and upload
- File decryption and download
- File sharing with other users
- Personal activity history
- Password management

## 🔧 Core Functionality

### File Encryption Process
1. User uploads file with encryption password
2. System generates salt and derives key using PBKDF2
3. File encrypted using AES-256 via Fernet
4. Original file deleted, encrypted version stored
5. Activity logged with user details

### File Decryption Process
1. User requests file download with password
2. System extracts salt from encrypted file
3. Key derived from password and salt
4. File decrypted and served to user
5. Access logged and counters updated

### Security Features
- **Password Hashing**: Werkzeug's secure password hashing
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt Generation**: Cryptographically secure random salts
- **Session Management**: Secure Flask sessions
- **Activity Logging**: Complete audit trail
- **File Access Control**: Owner and sharing permissions

## 📊 Database Schema

### Users Table
- User credentials and profile information
- Role-based access control
- Password reset token management
- Activity tracking (last login, creation date)

### Files Table
- File metadata and encryption details
- Owner and sharing information
- Access statistics and timestamps
- Encryption key hash for verification

### Activity Logs Table
- Complete user activity audit trail
- IP address tracking
- Timestamp and action details
- System security monitoring

## 🛠️ Configuration

### Environment Variables
- `FLASK_SECRET_KEY`: Flask session secret (auto-generated if not set)

### File Upload Settings
- **Max File Size**: 16MB
- **Allowed Types**: TXT, PDF, PNG, JPG, JPEG, GIF, DOC, DOCX, XLS, XLSX
- **Storage**: Encrypted files stored in `encrypted_files/` directory

### Security Settings
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Salt Length**: 16 bytes
- **Encryption**: AES-256 via Fernet

## 📋 Usage Examples

### Admin Tasks
1. **Add New User**
   - Login as admin → Admin Dashboard → Add New User
   - Fill in user details and assign role

2. **Monitor System Activity**
   - Admin Dashboard → System Logs
   - View real-time user activities and file operations

3. **Manage Users**
   - Admin Dashboard → Manage Users
   - View all users, their status, and last login times

### User Tasks
1. **Encrypt and Upload File**
   - Dashboard → Upload File
   - Select file, enter strong password, optionally share
   - File encrypted with AES-256 and stored securely

2. **Download and Decrypt File**
   - Dashboard → View Files → Download
   - Enter correct password to decrypt and download

3. **Share Files**
   - During upload, select users to share with
   - Shared users can decrypt with the same password

## 🔒 Security Best Practices

1. **Strong Passwords**: Use complex passwords for encryption
2. **Regular Monitoring**: Check system logs regularly
3. **User Management**: Remove inactive users promptly
4. **Backup Strategy**: Regular database backups recommended
5. **Network Security**: Use HTTPS in production

## 🏢 Oraco Kenya Integration

This system is designed specifically for Oraco Kenya's internal file security needs:
- Departmental user organization
- Kenyan email domain validation
- Local time zone considerations
- Organizational security policies compliance

## 📞 Support

For technical support or feature requests, contact the IT Department at Oraco Kenya.

## 📄 License

Proprietary software for Oraco Kenya internal use only.

---

**Built with security and usability in mind for Oraco Kenya's file encryption needs.**
