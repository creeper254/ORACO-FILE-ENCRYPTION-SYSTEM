# 🔐 ORACO Secure File Encryption System

A modern, secure file encryption and management system built with Flask, featuring AES-256 encryption, user management, and comprehensive admin controls.

## ✨ Features

### 🔒 Security Features
- **AES-256 Encryption**: Industry-standard encryption for all files
- **PBKDF2 Key Derivation**: Secure password-based key generation
- **Zero-Knowledge Architecture**: Passwords never stored on server
- **Access Control**: Granular file sharing and permissions
- **Audit Trail**: Complete activity logging for security monitoring

### 👥 User Features
- **File Upload & Encryption**: Secure file upload with custom passwords
- **File Sharing**: Share encrypted files with specific users
- **File Download**: Decrypt and download files with original passwords
- **Dashboard**: Personal file management and activity tracking
- **Modern UI**: Responsive, Bootstrap-based interface

### 🛡️ Admin Features
- **User Management**: Add, activate, deactivate, and delete users
- **File Monitoring**: View all encrypted files in the system
- **Activity Tracking**: Monitor user logins, file operations, and system activity
- **System Logs**: Comprehensive audit trail with IP addresses and user agents
- **Statistics Dashboard**: Real-time system statistics and metrics

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- pip (Python package installer)

### Installation

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd OracoSecureFileEncryptionSystem
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Reset database (creates fresh admin user)**
   ```bash
   python reset_db.py
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the system**
   - Open your browser and go to: `http://localhost:5000`
   - Login with admin credentials:
     - **Username**: `admin`
     - **Password**: `admin123`

## 📋 Default Admin Credentials

After running `reset_db.py`, you can login with:
- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@oraco.co.ke`

## 🔧 System Architecture

### Database Schema
- **Users Table**: User accounts, roles, and authentication
- **Files Table**: Encrypted file metadata and access control
- **Activity Logs Table**: Complete audit trail of all actions

### Security Implementation
- **Encryption**: AES-256 with PBKDF2 key derivation
- **Password Hashing**: Werkzeug's secure password hashing
- **Session Management**: Flask session-based authentication
- **Access Control**: Role-based permissions (admin/user)

## 📊 Admin Dashboard Features

### Statistics Overview
- Total users in the system
- Total encrypted files
- Today's activity count
- Today's login count

### User Management
- **Add Users**: Create new user accounts with roles
- **Activate/Deactivate**: Enable or disable user accounts
- **Delete Users**: Remove users and their associated files
- **User Status**: Monitor user login activity and status

### File Management
- **View All Files**: See all encrypted files in the system
- **File Details**: File type, size, owner, access count
- **Delete Files**: Remove files from the system
- **Sharing Info**: View which users have access to files

### System Monitoring
- **Activity Logs**: Complete audit trail with timestamps
- **IP Tracking**: Monitor user access locations
- **User Agents**: Track browser and device information
- **Real-time Stats**: Live system statistics

## 🔐 File Encryption Process

1. **Upload**: User selects file and provides encryption password
2. **Encryption**: File encrypted using AES-256 with PBKDF2 key derivation
3. **Storage**: Encrypted file stored, original file deleted
4. **Metadata**: File information stored in database
5. **Access**: Users can download with original password

## 👤 User Roles

### Admin Users
- Full system access
- User management capabilities
- File monitoring and deletion
- System logs access
- Statistics dashboard

### Regular Users
- Upload and encrypt files
- Share files with other users
- Download their own and shared files
- View personal dashboard and activity

## 📁 Supported File Types

- **Documents**: PDF, DOC, DOCX, TXT
- **Spreadsheets**: XLS, XLSX
- **Images**: PNG, JPG, JPEG, GIF
- **Archives**: ZIP
- **Media**: MP4, MP3

## 🛠️ Configuration

### Environment Variables
- `EMAIL_ADDRESS`: Gmail address for password reset
- `EMAIL_PASSWORD`: Gmail app password
- `SECRET_KEY`: Flask secret key for sessions

### File Size Limits
- Maximum file size: 16MB
- Configurable in `app.py`

## 🔍 Troubleshooting

### Admin Login Issues
1. Run `python reset_db.py` to reset database
2. Use default credentials: `admin` / `admin123`
3. Check if database file exists: `oraco_system.db`

### File Upload Issues
1. Check file size (max 16MB)
2. Verify file type is supported
3. Ensure upload directory has write permissions

### Email Issues
1. Verify Gmail credentials in `app.py`
2. Use Gmail App Password, not regular password
3. Check SMTP settings

## 📈 System Requirements

- **Python**: 3.7 or higher
- **Memory**: 512MB RAM minimum
- **Storage**: Depends on file uploads
- **Network**: For email functionality

## 🔒 Security Best Practices

1. **Change Default Admin Password**: Immediately after first login
2. **Regular Backups**: Backup database and encrypted files
3. **Monitor Logs**: Regularly check system activity logs
4. **User Management**: Deactivate unused accounts
5. **File Cleanup**: Remove unnecessary encrypted files

## 📞 Support

For technical support or questions:
- Check the system logs for error details
- Verify all dependencies are installed
- Ensure proper file permissions

## 📄 License

This project is proprietary software for ORACO Kenya.

---

**⚠️ Important**: This system handles sensitive data. Always follow security best practices and regularly update passwords and access controls.
