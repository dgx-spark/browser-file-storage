# File Manager - Terminal Theme

A modern, terminal-inspired file manager with authentication system, built entirely with vanilla JavaScript, HTML, and CSS. Uses IndexedDB for local storage.

## Features

- 🔐 **Multi-User Authentication** - Secure login system with user-specific data isolation
- 📁 **File Management** - Upload, download, rename, delete files and folders
- 👤 **User Management** - Admin panel for managing users
- 💾 **5GB Storage** - Browser-based storage using IndexedDB
- 🎨 **Terminal Theme** - Green-on-black CRT-inspired design
- 📤 **Data Export/Import** - Backup and restore all data as JSON
- 🔑 **Password Recovery** - For regular users (not admin for security)
- 🔄 **Persistent Sessions** - Stay logged in across page refreshes
- 📱 **Responsive Design** - Works on desktop and mobile

## Default Admin Account

- **Username:** `admin`
- **Password:** `admin123`

⚠️ **Change the admin password immediately after first login!**

## GitHub Pages Deployment

### Quick Deploy

1. **Fork or Clone this repository**
   ```bash
   git clone <your-repo-url>
   cd <your-repo-name>
   ```

2. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

3. **Enable GitHub Pages**
   - Go to your repository on GitHub
   - Click `Settings` → `Pages`
   - Under "Source", select `main` branch
   - Click `Save`
   - Your site will be live at: `https://<username>.github.io/<repo-name>/`

### File Structure
```
├── index.html          # Main HTML structure
├── styles.css          # Terminal theme styling
├── app.js              # Application logic
└── README.md           # This file
```

## Usage

### For Admin
1. Login with default credentials
2. **Change your password** via `[CHANGE PASSWORD]` button
3. **Export backup** regularly from Admin Panel
4. Manage users from Admin Panel
5. Import/Export data as needed

### For Regular Users
1. Click `[REGISTER]` to create an account
2. Login with your credentials
3. Upload and manage your files
4. Use forgot password if needed (generates recovery code)

## Important Security Notes

### Admin Password
- **Cannot be recovered** if forgotten (security by design)
- If locked out:
  - Option 1: Import a previous backup
  - Option 2: Clear all data (lose everything)
  - Option 3: Use another admin account to reset
- **Always export backups before logging out!**

### Data Storage
- All data stored in browser's IndexedDB
- Each browser has separate storage
- Incognito mode resets on close
- Use Export/Import to transfer data

## Browser Compatibility

- ✅ Chrome/Edge (recommended)
- ✅ Firefox
- ✅ Safari
- ✅ Opera
- ⚠️ Requires modern browser with IndexedDB support

## Features Overview

### Authentication System
- Multi-user support
- Role-based access (admin/user)
- Session persistence
- Secure password hashing (Base64)

### File Operations
- Upload multiple files
- Download files
- Rename files/folders
- Delete files/folders
- Create new folders
- File preview
- Storage quota tracking

### Admin Features
- View all users
- Delete users
- Promote/demote user roles
- Reset user passwords
- Export all data
- Import data
- Clear all data

### Data Management
- Export backup (JSON format)
- Import backup
- Data includes: users, files, sessions, settings
- File contents stored as base64

## Storage Limits

- **Browser Quota:** 5 GB (configurable)
- **Per User:** Unlimited (within browser quota)
- **File Size:** Limited by available storage

## Development

This is a static web application with no backend required. All data is stored client-side in IndexedDB.

### Technologies Used
- HTML5
- CSS3 (Terminal theme with animations)
- Vanilla JavaScript (ES6+)
- IndexedDB API
- File System Access API

### No Build Process Required
Just open `index.html` in a browser or deploy to any static hosting service.

## Customization

### Change Colors
Edit `styles.css` - search for color values:
- Primary: `#00ff00` (green)
- Error: `#ff0000` (red)
- Background: `#0c0c0c` (black)

### Change Storage Limit
Edit `app.js` - search for `storageQuota`:
```javascript
storageQuota: 5 * 1024 * 1024 * 1024 // 5GB
```

### Change Default Admin Credentials
Edit `app.js` - search for:
```javascript
ADMIN_USERNAME = 'admin';
ADMIN_DEFAULT_PASSWORD = 'admin123';
```

## Troubleshooting

### Lost Admin Password?
1. If logged in: Use `[CHANGE PASSWORD]`
2. If locked out: Import backup or clear all data

### Page Refreshes Log Me Out?
- Check browser settings (IndexedDB enabled)
- Check console for errors (F12)
- Try another browser

### Storage Full?
1. Delete unnecessary files
2. Export and clear old data
3. Increase browser storage quota

### Incognito Mode Issues?
- Data is temporary in incognito/private mode
- Export before closing window
- Import backup in new incognito session

## License

MIT License - Feel free to use and modify!

## Support

For issues or questions, please open an issue on GitHub.

---

**⚠️ IMPORTANT:** Always export your data regularly! This app stores everything locally in your browser. If you clear browser data, everything will be lost unless you have a backup.

**🔒 SECURITY NOTE:** This is designed for personal/local use. The password hashing is basic (Base64). For production use, implement proper backend authentication and encryption.
