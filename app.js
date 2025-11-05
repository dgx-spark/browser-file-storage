// User Authentication Manager
class AuthManager {
    constructor() {
        this.dbName = 'FileManagerAuthDB';
        this.dbVersion = 1;
        this.db = null;
        this.currentUser = null;
        this.ADMIN_USERNAME = 'admin';
        this.ADMIN_DEFAULT_PASSWORD = 'admin123';
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.dbVersion);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                this.ensureAdminExists();
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;

                // Create users store
                if (!db.objectStoreNames.contains('users')) {
                    const userStore = db.createObjectStore('users', { keyPath: 'username' });
                    userStore.createIndex('email', 'email', { unique: true });
                    userStore.createIndex('role', 'role', { unique: false });
                }

                // Create sessions store
                if (!db.objectStoreNames.contains('sessions')) {
                    db.createObjectStore('sessions', { keyPath: 'username' });
                }

                // Create user settings store
                if (!db.objectStoreNames.contains('userSettings')) {
                    db.createObjectStore('userSettings', { keyPath: 'username' });
                }
            };
        });
    }

    async ensureAdminExists() {
        const transaction = this.db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');

        const checkRequest = store.get(this.ADMIN_USERNAME);
        checkRequest.onsuccess = () => {
            if (!checkRequest.result) {
                // Create admin account
                const hashedPassword = btoa(this.ADMIN_DEFAULT_PASSWORD + this.ADMIN_USERNAME);
                const admin = {
                    username: this.ADMIN_USERNAME,
                    password: hashedPassword,
                    email: 'admin@filemanager.local',
                    role: 'admin',
                    createdAt: new Date().toISOString(),
                    avatar: '#ff0000'
                };
                store.add(admin);
                console.log('Admin account created. Username: admin, Password: admin123');
            }
        };
    }

    async register(username, password, email, role = 'user') {
        const transaction = this.db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');

        return new Promise(async (resolve, reject) => {
            // Check if user exists
            const checkRequest = store.get(username);
            checkRequest.onsuccess = () => {
                if (checkRequest.result) {
                    reject(new Error('Username already exists'));
                    return;
                }

                // Hash password (simple for demo - use proper hashing in production)
                const hashedPassword = btoa(password + username);

                const user = {
                    username: username,
                    password: hashedPassword,
                    email: email,
                    role: role,
                    createdAt: new Date().toISOString(),
                    avatar: this.generateAvatar(username)
                };

                const addRequest = store.add(user);
                addRequest.onsuccess = () => {
                    // Create default settings
                    this.createDefaultSettings(username);
                    resolve(user);
                };
                addRequest.onerror = () => reject(addRequest.error);
            };
        });
    }

    async login(username, password) {
        const transaction = this.db.transaction(['users', 'sessions'], 'readwrite');
        const userStore = transaction.objectStore('users');
        const sessionStore = transaction.objectStore('sessions');

        return new Promise((resolve, reject) => {
            const request = userStore.get(username);
            request.onsuccess = () => {
                const user = request.result;
                if (!user) {
                    reject(new Error('User not found'));
                    return;
                }

                const hashedPassword = btoa(password + username);
                if (user.password !== hashedPassword) {
                    reject(new Error('Invalid password'));
                    return;
                }

                // Create session
                const session = {
                    username: username,
                    loginTime: new Date().toISOString(),
                    token: this.generateToken()
                };

                sessionStore.put(session);
                this.currentUser = user;
                localStorage.setItem('currentUser', username);
                resolve(user);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async logout() {
        if (this.currentUser) {
            const transaction = this.db.transaction(['sessions'], 'readwrite');
            const store = transaction.objectStore('sessions');
            store.delete(this.currentUser.username);
            this.currentUser = null;
            localStorage.removeItem('currentUser');
        }
    }

    async getCurrentUser() {
        const username = localStorage.getItem('currentUser');
        if (!username) return null;

        const transaction = this.db.transaction(['users'], 'readonly');
        const store = transaction.objectStore('users');

        return new Promise((resolve, reject) => {
            const request = store.get(username);
            request.onsuccess = () => {
                this.currentUser = request.result;
                resolve(request.result);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async createDefaultSettings(username) {
        const transaction = this.db.transaction(['userSettings'], 'readwrite');
        const store = transaction.objectStore('userSettings');

        const settings = {
            username: username,
            theme: 'terminal',
            view: 'grid',
            storageQuota: 5 * 1024 * 1024 * 1024
        };

        store.put(settings);
    }

    async getUserSettings(username) {
        const transaction = this.db.transaction(['userSettings'], 'readonly');
        const store = transaction.objectStore('userSettings');

        return new Promise((resolve, reject) => {
            const request = store.get(username);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async updateUserSettings(username, settings) {
        const transaction = this.db.transaction(['userSettings'], 'readwrite');
        const store = transaction.objectStore('userSettings');

        return new Promise((resolve, reject) => {
            const request = store.put({ username, ...settings });
            request.onsuccess = () => resolve(true);
            request.onerror = () => reject(request.error);
        });
    }

    generateToken() {
        return btoa(Date.now() + Math.random().toString(36));
    }

    generateAvatar(username) {
        const colors = ['#00ff00', '#00cc00', '#00aa00', '#008800'];
        const color = colors[username.length % colors.length];
        return color;
    }

    isAdmin(user) {
        return user && user.role === 'admin';
    }

    async getAllUsers() {
        const transaction = this.db.transaction(['users'], 'readonly');
        const store = transaction.objectStore('users');

        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => {
                // Don't return passwords
                const users = request.result.map(u => ({
                    username: u.username,
                    email: u.email,
                    role: u.role,
                    createdAt: u.createdAt,
                    avatar: u.avatar
                }));
                resolve(users);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async deleteUser(username) {
        if (username === this.ADMIN_USERNAME) {
            throw new Error('Cannot delete admin account');
        }

        const transaction = this.db.transaction(['users', 'sessions', 'userSettings'], 'readwrite');
        
        return new Promise((resolve, reject) => {
            transaction.objectStore('users').delete(username);
            transaction.objectStore('sessions').delete(username);
            transaction.objectStore('userSettings').delete(username);
            
            transaction.oncomplete = () => resolve(true);
            transaction.onerror = () => reject(transaction.error);
        });
    }

    async updateUserRole(username, newRole) {
        if (username === this.ADMIN_USERNAME) {
            throw new Error('Cannot modify admin account');
        }

        const transaction = this.db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');

        return new Promise((resolve, reject) => {
            const getRequest = store.get(username);
            getRequest.onsuccess = () => {
                const user = getRequest.result;
                if (!user) {
                    reject(new Error('User not found'));
                    return;
                }

                user.role = newRole;
                const updateRequest = store.put(user);
                updateRequest.onsuccess = () => resolve(true);
                updateRequest.onerror = () => reject(updateRequest.error);
            };
        });
    }

    async resetUserPassword(username, newPassword) {
        if (username === this.ADMIN_USERNAME) {
            throw new Error('Cannot reset admin password from here');
        }

        const transaction = this.db.transaction(['users'], 'readwrite');
        const store = transaction.objectStore('users');

        return new Promise((resolve, reject) => {
            const getRequest = store.get(username);
            getRequest.onsuccess = () => {
                const user = getRequest.result;
                if (!user) {
                    reject(new Error('User not found'));
                    return;
                }

                user.password = btoa(newPassword + username);
                const updateRequest = store.put(user);
                updateRequest.onsuccess = () => resolve(true);
                updateRequest.onerror = () => reject(updateRequest.error);
            };
        });
    }

    async getUserFileCount(username) {
        // This will be called from the admin panel
        if (!fileDB.db) {
            return 0;
        }
        
        try {
            const transaction = fileDB.db.transaction(['files'], 'readonly');
            const store = transaction.objectStore('files');
            const index = store.index('userId');

            return new Promise((resolve, reject) => {
                const request = index.count(username);
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => resolve(0); // Return 0 on error
            });
        } catch (error) {
            console.error('Error getting file count:', error);
            return 0;
        }
    }

    async getUserStorageSize(username) {
        if (!fileDB.db) {
            return 0;
        }
        
        try {
            const transaction = fileDB.db.transaction(['files'], 'readonly');
            const store = transaction.objectStore('files');
            const index = store.index('userId');

            return new Promise((resolve, reject) => {
                const request = index.getAll(username);
                request.onsuccess = () => {
                    const files = request.result;
                    const totalSize = files.reduce((sum, file) => sum + (file.sizeBytes || 0), 0);
                    resolve(totalSize);
                };
                request.onerror = () => resolve(0); // Return 0 on error
            });
        } catch (error) {
            console.error('Error getting storage size:', error);
            return 0;
        }
    }
}

// IndexedDB Database Manager
class FileDatabase {
    constructor() {
        this.dbName = 'FileManagerDB';
        this.dbVersion = 2;
        this.db = null;
        this.currentUser = null;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.dbVersion);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;

                // Create files object store with userId
                if (!db.objectStoreNames.contains('files')) {
                    const fileStore = db.createObjectStore('files', { keyPath: 'id', autoIncrement: true });
                    fileStore.createIndex('name', 'name', { unique: false });
                    fileStore.createIndex('path', 'path', { unique: false });
                    fileStore.createIndex('type', 'type', { unique: false });
                    fileStore.createIndex('starred', 'starred', { unique: false });
                    fileStore.createIndex('userId', 'userId', { unique: false });
                } else if (event.oldVersion < 2) {
                    // Add userId index if upgrading
                    const transaction = event.target.transaction;
                    const fileStore = transaction.objectStore('files');
                    if (!fileStore.indexNames.contains('userId')) {
                        fileStore.createIndex('userId', 'userId', { unique: false });
                    }
                }

                // Create file data store (for actual file blobs)
                if (!db.objectStoreNames.contains('fileData')) {
                    db.createObjectStore('fileData', { keyPath: 'fileId' });
                }
            };
        });
    }

    setUser(username) {
        this.currentUser = username;
    }

    async addFile(fileMetadata, fileBlob = null) {
        const transaction = this.db.transaction(['files', 'fileData'], 'readwrite');
        const fileStore = transaction.objectStore('files');
        const fileDataStore = transaction.objectStore('fileData');

        return new Promise((resolve, reject) => {
            // Add userId to metadata
            fileMetadata.userId = this.currentUser;
            
            const request = fileStore.add(fileMetadata);

            request.onsuccess = async () => {
                const fileId = request.result;
                
                // Store file blob if provided
                if (fileBlob) {
                    await fileDataStore.put({ fileId: fileId, blob: fileBlob });
                }
                
                resolve(fileId);
            };

            request.onerror = () => reject(request.error);
        });
    }

    async getAllFiles() {
        const transaction = this.db.transaction(['files'], 'readonly');
        const store = transaction.objectStore('files');
        const index = store.index('userId');

        return new Promise((resolve, reject) => {
            const request = index.getAll(this.currentUser);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getFile(id) {
        const transaction = this.db.transaction(['files'], 'readonly');
        const store = transaction.objectStore('files');

        return new Promise((resolve, reject) => {
            const request = store.get(id);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getFileBlob(fileId) {
        const transaction = this.db.transaction(['fileData'], 'readonly');
        const store = transaction.objectStore('fileData');

        return new Promise((resolve, reject) => {
            const request = store.get(fileId);
            request.onsuccess = () => {
                const result = request.result;
                resolve(result ? result.blob : null);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async updateFile(id, updates) {
        const file = await this.getFile(id);
        if (!file) return false;

        const updatedFile = { ...file, ...updates };
        const transaction = this.db.transaction(['files'], 'readwrite');
        const store = transaction.objectStore('files');

        return new Promise((resolve, reject) => {
            const request = store.put(updatedFile);
            request.onsuccess = () => resolve(true);
            request.onerror = () => reject(request.error);
        });
    }

    async deleteFile(id) {
        const transaction = this.db.transaction(['files', 'fileData'], 'readwrite');
        const fileStore = transaction.objectStore('files');
        const fileDataStore = transaction.objectStore('fileData');

        return new Promise((resolve, reject) => {
            fileStore.delete(id);
            fileDataStore.delete(id);
            
            transaction.oncomplete = () => resolve(true);
            transaction.onerror = () => reject(transaction.error);
        });
    }

    async getTotalSize() {
        const files = await this.getAllFiles();
        return files.reduce((total, file) => {
            if (file.sizeBytes && file.userId === this.currentUser) {
                return total + file.sizeBytes;
            }
            return total;
        }, 0);
    }
}

// Authentication and File Manager State
const authManager = new AuthManager();
const fileDB = new FileDatabase();
let files = [];
let currentView = 'grid';
let currentFilter = 'all';
let currentPath = 'home';
let selectedFile = null;

// Icon mapping
const icons = {
    folder: '📁',
    document: '📄',
    image: '🖼️',
    video: '🎥',
    audio: '🎵',
    archive: '📦',
    default: '📄'
};

// Initialize
async function init() {
    try {
        await authManager.init();
        await fileDB.init();
        
        // Check if user is logged in
        const user = await authManager.getCurrentUser();
        if (!user) {
            showLoginScreen();
            return;
        }

        fileDB.setUser(user.username);
        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        setupEventListeners();
        updateUserInfo(user);
        console.log('File Manager initialized with IndexedDB for user:', user.username);
    } catch (error) {
        console.error('Error initializing file manager:', error);
        showLoginScreen();
    }
}

// Show login screen
function showLoginScreen() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';
}

// Hide login screen
function hideLoginScreen() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
}

// Update user info in header
function updateUserInfo(user) {
    const userInfo = document.getElementById('userInfo');
    if (userInfo) {
        const isAdmin = authManager.isAdmin(user);
        userInfo.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 10px; height: 10px; background: ${user.avatar}; box-shadow: 0 0 10px ${user.avatar};"></div>
                <span style="text-transform: uppercase; letter-spacing: 1px;">${user.username}</span>
                ${isAdmin ? '<span style="color: #ff0000; font-size: 10px;">[ADMIN]</span>' : ''}
                ${isAdmin ? '<button class="btn btn-secondary" onclick="showAdminPanel()" style="padding: 5px 10px; font-size: 11px;">[ADMIN PANEL]</button>' : ''}
                <button class="btn btn-secondary" onclick="handleLogout()" style="padding: 5px 10px; font-size: 11px;">[LOGOUT]</button>
            </div>
        `;
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showStatus('Please enter username and password', 'error');
        return;
    }

    try {
        const user = await authManager.login(username, password);
        fileDB.setUser(user.username);
        hideLoginScreen();
        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        setupEventListeners();
        updateUserInfo(user);
        showStatus(`Welcome back, ${user.username}!`);
    } catch (error) {
        showStatus(error.message, 'error');
    }
}

// Handle registration
async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('registerConfirmPassword').value;

    if (!username || !email || !password) {
        showStatus('Please fill all fields', 'error');
        return;
    }

    if (password !== confirmPassword) {
        showStatus('Passwords do not match', 'error');
        return;
    }

    if (password.length < 4) {
        showStatus('Password must be at least 4 characters', 'error');
        return;
    }

    try {
        const user = await authManager.register(username, password, email);
        await authManager.login(username, password);
        fileDB.setUser(user.username);
        hideLoginScreen();
        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        setupEventListeners();
        updateUserInfo(user);
        showStatus(`Account created! Welcome, ${user.username}!`);
    } catch (error) {
        showStatus(error.message, 'error');
    }
}

// Handle logout
async function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        await authManager.logout();
        files = [];
        currentPath = 'home';
        selectedFile = null;
        showLoginScreen();
        showStatus('Logged out successfully');
    }
}

// Toggle between login and register forms
function toggleAuthForm() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const toggleText = document.getElementById('toggleText');
    const toggleLink = document.getElementById('toggleLink');
    
    if (loginForm.style.display === 'none') {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        toggleText.textContent = '// NEW USER?';
        toggleLink.textContent = '[REGISTER]';
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        toggleText.textContent = '// HAVE AN ACCOUNT?';
        toggleLink.textContent = '[LOGIN]';
    }
}

// Load files from database
async function loadFilesFromDB() {
    try {
        files = await fileDB.getAllFiles();
        
        // If no files exist, create some demo folders
        if (files.length === 0) {
            await createDemoStructure();
        }
    } catch (error) {
        console.error('Error loading files:', error);
    }
}

// Create demo folder structure
async function createDemoStructure() {
    const demoFolders = [
        { name: 'Documents', type: 'folder', size: '-', sizeBytes: 0, modified: new Date().toISOString(), starred: false, path: 'home' },
        { name: 'Images', type: 'folder', size: '-', sizeBytes: 0, modified: new Date().toISOString(), starred: false, path: 'home' },
        { name: 'Videos', type: 'folder', size: '-', sizeBytes: 0, modified: new Date().toISOString(), starred: false, path: 'home' }
    ];

    for (const folder of demoFolders) {
        await fileDB.addFile(folder);
    }

    await loadFilesFromDB();
}

// Format modified date
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
    if (days < 30) return `${Math.floor(days / 7)} week${Math.floor(days / 7) > 1 ? 's' : ''} ago`;
    return date.toLocaleDateString();
}

// Render files
function renderFiles() {
    const fileArea = document.getElementById('fileArea');
    const filteredFiles = filterFiles();

    if (filteredFiles.length === 0) {
        fileArea.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📂</div>
                <div class="empty-state-text">// NO FILES FOUND</div>
                <div style="color: rgba(0, 255, 0, 0.5); font-size: 12px;">$ upload_files_to_begin</div>
            </div>
        `;
        fileArea.classList.remove('file-grid', 'file-list');
        return;
    }

    fileArea.className = currentView === 'grid' ? 'file-area' : 'file-area';
    const container = document.createElement('div');
    container.className = currentView === 'grid' ? 'file-grid' : 'file-list';

    filteredFiles.forEach(file => {
        const fileElement = createFileElement(file);
        container.appendChild(fileElement);
    });

    fileArea.innerHTML = '';
    fileArea.appendChild(container);
}

// Create file element
function createFileElement(file) {
    const element = document.createElement('div');
    const icon = icons[file.type] || icons.default;
    const modifiedText = formatDate(file.modified);

    if (currentView === 'grid') {
        element.className = 'file-item';
        element.innerHTML = `
            <div class="file-icon">${icon}</div>
            <div class="file-name">${file.name}</div>
            <div class="file-meta">${file.size} • ${modifiedText}</div>
        `;
    } else {
        element.className = 'list-item';
        element.innerHTML = `
            <div class="list-icon">${icon}</div>
            <div class="list-info">
                <div class="list-name">${file.name}</div>
                <div class="list-meta">${file.size} • ${modifiedText}</div>
            </div>
            ${file.starred ? '<div style="font-size: 20px;">⭐</div>' : ''}
        `;
    }

    element.onclick = (e) => selectFile(file, element, e);
    element.oncontextmenu = (e) => showContextMenu(e, file);
    element.ondblclick = () => {
        if (file.type === 'folder') {
            openFolder(file);
        } else {
            openFile();
        }
    };

    return element;
}

// Filter files
function filterFiles() {
    let filtered = files.filter(f => f.path === currentPath);

    if (currentFilter === 'recent') {
        filtered.sort((a, b) => a.modified.localeCompare(b.modified));
    } else if (currentFilter === 'starred') {
        filtered = filtered.filter(f => f.starred);
    } else if (currentFilter !== 'all') {
        filtered = filtered.filter(f => f.type === currentFilter);
    }

    const searchTerm = document.getElementById('searchBox').value.toLowerCase();
    if (searchTerm) {
        filtered = filtered.filter(f => f.name.toLowerCase().includes(searchTerm));
    }

    return filtered;
}

// Select file
function selectFile(file, element, e) {
    if (e) e.stopPropagation();
    
    document.querySelectorAll('.file-item, .list-item').forEach(el => {
        el.classList.remove('selected');
    });

    element.classList.add('selected');
    selectedFile = file;
}

// Set view
function setView(view) {
    currentView = view;
    document.getElementById('gridBtn').classList.toggle('active', view === 'grid');
    document.getElementById('listBtn').classList.toggle('active', view === 'list');
    renderFiles();
}

// Filter by type
function filterByType(type) {
    currentFilter = type;
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.classList.add('active');
    renderFiles();
}

// Show context menu
function showContextMenu(e, file) {
    e.preventDefault();
    const menu = document.getElementById('contextMenu');
    menu.style.display = 'block';
    menu.style.left = e.pageX + 'px';
    menu.style.top = e.pageY + 'px';
    selectedFile = file;
}

// Hide context menu
function hideContextMenu() {
    document.getElementById('contextMenu').style.display = 'none';
}

// Open file
async function openFile() {
    if (selectedFile) {
        if (selectedFile.type === 'folder') {
            openFolder(selectedFile);
        } else {
            // Try to download/open the file
            const blob = await fileDB.getFileBlob(selectedFile.id);
            if (blob) {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.target = '_blank';
                a.click();
                URL.revokeObjectURL(url);
            } else {
                alert(`Opening: ${selectedFile.name}\n(File blob not available - this was a demo file)`);
            }
        }
    }
    hideContextMenu();
}

// Open folder
function openFolder(folder) {
    currentPath = folder.name;
    updateBreadcrumb();
    renderFiles();
}

// Navigate to path
function navigateTo(path) {
    currentPath = path;
    updateBreadcrumb();
    renderFiles();
}

// Update breadcrumb
function updateBreadcrumb() {
    const breadcrumb = document.getElementById('breadcrumb');
    breadcrumb.innerHTML = '<div class="breadcrumb-item" onclick="navigateTo(\'home\')">~/ HOME</div>';
    
    if (currentPath !== 'home') {
        breadcrumb.innerHTML += `<div style="color: rgba(0, 255, 0, 0.5);">/</div>
            <div class="breadcrumb-item">${currentPath.toUpperCase()}</div>`;
    }
}

// Rename file
async function renameFile() {
    if (selectedFile) {
        document.getElementById('renameInput').value = selectedFile.name;
        showModal('renameModal');
    }
    hideContextMenu();
}

// Confirm rename
async function confirmRename() {
    const newName = document.getElementById('renameInput').value.trim();
    if (newName && selectedFile) {
        try {
            await fileDB.updateFile(selectedFile.id, { name: newName });
            await loadFilesFromDB();
            renderFiles();
            closeModal('renameModal');
            showStatus('File renamed successfully');
        } catch (error) {
            console.error('Error renaming file:', error);
            showStatus('Error renaming file', 'error');
        }
    }
}

// Download file
async function downloadFile() {
    if (selectedFile && selectedFile.type !== 'folder') {
        try {
            const blob = await fileDB.getFileBlob(selectedFile.id);
            if (blob) {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = selectedFile.name;
                a.click();
                URL.revokeObjectURL(url);
            } else {
                alert('File data not available (demo file)');
            }
        } catch (error) {
            console.error('Error downloading file:', error);
            alert('Error downloading file');
        }
    }
    hideContextMenu();
}

// Toggle star
async function toggleStar() {
    if (selectedFile) {
        try {
            await fileDB.updateFile(selectedFile.id, { starred: !selectedFile.starred });
            await loadFilesFromDB();
            renderFiles();
        } catch (error) {
            console.error('Error toggling star:', error);
        }
    }
    hideContextMenu();
}

// Delete file
async function deleteFile() {
    if (selectedFile && confirm(`Delete ${selectedFile.name}?`)) {
        try {
            await fileDB.deleteFile(selectedFile.id);
            await loadFilesFromDB();
            await updateStorageInfo();
            selectedFile = null;
            renderFiles();
            showStatus('File deleted successfully');
        } catch (error) {
            console.error('Error deleting file:', error);
            showStatus('Error deleting file', 'error');
        }
    }
    hideContextMenu();
}

// Show upload modal
function showUploadModal() {
    showModal('uploadModal');
}

// Upload files
async function uploadFiles() {
    const fileInput = document.getElementById('fileInput');
    const uploadedFiles = Array.from(fileInput.files);

    if (uploadedFiles.length === 0) {
        alert('Please select files to upload');
        return;
    }

    try {
        for (const file of uploadedFiles) {
            const fileMetadata = {
                name: file.name,
                type: getFileType(file.name),
                size: formatFileSize(file.size),
                sizeBytes: file.size,
                modified: new Date().toISOString(),
                starred: false,
                path: currentPath
            };

            // Store metadata and file blob
            await fileDB.addFile(fileMetadata, file);
        }

        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        closeModal('uploadModal');
        fileInput.value = '';
        showStatus(`${uploadedFiles.length} file(s) uploaded successfully`);
    } catch (error) {
        console.error('Error uploading files:', error);
        showStatus('Error uploading files', 'error');
    }
}

// Get file type
function getFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'].includes(ext)) return 'image';
    if (['mp4', 'avi', 'mov', 'mkv'].includes(ext)) return 'video';
    if (['mp3', 'wav', 'ogg', 'flac'].includes(ext)) return 'audio';
    if (['pdf', 'doc', 'docx', 'txt', 'xlsx', 'pptx'].includes(ext)) return 'document';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'archive';
    return 'default';
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Show new folder modal
function showNewFolderModal() {
    showModal('newFolderModal');
}

// Create folder
async function createFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    if (folderName) {
        try {
            const newFolder = {
                name: folderName,
                type: 'folder',
                size: '-',
                sizeBytes: 0,
                modified: new Date().toISOString(),
                starred: false,
                path: currentPath
            };
            
            await fileDB.addFile(newFolder);
            await loadFilesFromDB();
            renderFiles();
            closeModal('newFolderModal');
            document.getElementById('folderNameInput').value = '';
            showStatus('Folder created successfully');
        } catch (error) {
            console.error('Error creating folder:', error);
            showStatus('Error creating folder', 'error');
        }
    }
}

// Update storage info
async function updateStorageInfo() {
    try {
        const totalBytes = await fileDB.getTotalSize();
        const maxBytes = 5 * 1024 * 1024 * 1024; // 5 GB storage limit
        const percentage = (totalBytes / maxBytes) * 100;

        document.querySelector('.storage-fill').style.width = Math.min(percentage, 100) + '%';
        document.querySelector('.storage-text:last-child').textContent = 
            `${formatFileSize(totalBytes)} / ${formatFileSize(maxBytes)}`;
    } catch (error) {
        console.error('Error updating storage info:', error);
    }
}

// Show status notification
function showStatus(message, type = 'success') {
    const indicator = document.getElementById('statusIndicator');
    const icon = document.getElementById('statusIcon');
    const text = document.getElementById('statusText');

    indicator.className = 'status-indicator show ' + type;
    icon.textContent = type === 'success' ? '✓' : '✗';
    text.textContent = message;

    setTimeout(() => {
        indicator.classList.remove('show');
    }, 3000);
}

// Search files
function searchFiles() {
    renderFiles();
}

// Show modal
function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

// Close modal
function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// Setup event listeners
function setupEventListeners() {
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.context-menu')) {
            hideContextMenu();
        }
        if (!e.target.closest('.file-item') && !e.target.closest('.list-item')) {
            selectedFile = null;
            document.querySelectorAll('.file-item, .list-item').forEach(el => {
                el.classList.remove('selected');
            });
        }
    });

    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Delete' && selectedFile) {
            deleteFile();
        }
        if (e.key === 'F2' && selectedFile) {
            renameFile();
        }
    });
}

// Admin Panel Functions
async function showAdminPanel() {
    const user = authManager.currentUser;
    console.log('Current user:', user);
    console.log('Is admin?', authManager.isAdmin(user));
    
    if (!authManager.isAdmin(user)) {
        showStatus('Access denied: Admin only', 'error');
        return;
    }

    try {
        console.log('Loading admin panel...');
        const users = await authManager.getAllUsers();
        console.log('Users loaded:', users);
        
        const usersWithStats = await Promise.all(users.map(async (u) => {
            const fileCount = await authManager.getUserFileCount(u.username);
            const storageSize = await authManager.getUserStorageSize(u.username);
            return { ...u, fileCount, storageSize };
        }));

        console.log('Users with stats:', usersWithStats);
        renderAdminPanel(usersWithStats);
        showModal('adminPanel');
    } catch (error) {
        console.error('Error loading admin panel:', error);
        showStatus('Error loading admin panel: ' + error.message, 'error');
    }
}

function renderAdminPanel(users) {
    const usersList = document.getElementById('adminUsersList');
    const adminStats = document.getElementById('adminStats');
    
    if (!usersList || !adminStats) {
        console.error('Admin panel elements not found');
        return;
    }
    
    const totalUsers = users.length;
    const totalStorage = users.reduce((sum, u) => sum + (u.storageSize || 0), 0);
    const totalFiles = users.reduce((sum, u) => sum + (u.fileCount || 0), 0);

    adminStats.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px;">
            <div style="border: 1px solid rgba(0, 255, 0, 0.3); padding: 15px; background: rgba(0, 255, 0, 0.05);">
                <div style="font-size: 11px; color: rgba(0, 255, 0, 0.7);">TOTAL USERS</div>
                <div style="font-size: 24px; font-weight: 700; color: #00ff00;">${totalUsers}</div>
            </div>
            <div style="border: 1px solid rgba(0, 255, 0, 0.3); padding: 15px; background: rgba(0, 255, 0, 0.05);">
                <div style="font-size: 11px; color: rgba(0, 255, 0, 0.7);">TOTAL FILES</div>
                <div style="font-size: 24px; font-weight: 700; color: #00ff00;">${totalFiles}</div>
            </div>
            <div style="border: 1px solid rgba(0, 255, 0, 0.3); padding: 15px; background: rgba(0, 255, 0, 0.05);">
                <div style="font-size: 11px; color: rgba(0, 255, 0, 0.7);">TOTAL STORAGE</div>
                <div style="font-size: 24px; font-weight: 700; color: #00ff00;">${formatFileSize(totalStorage)}</div>
            </div>
        </div>
    `;

    usersList.innerHTML = users.map(user => `
        <div style="border: 1px solid rgba(0, 255, 0, 0.3); padding: 15px; margin-bottom: 10px; background: rgba(0, 255, 0, 0.05);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <div style="width: 8px; height: 8px; background: ${user.avatar}; box-shadow: 0 0 5px ${user.avatar};"></div>
                        <span style="font-weight: 700; color: #00ff00;">${user.username}</span>
                        <span style="font-size: 10px; padding: 2px 6px; border: 1px solid ${user.role === 'admin' ? '#ff0000' : '#00ff00'}; color: ${user.role === 'admin' ? '#ff0000' : '#00ff00'};">${user.role.toUpperCase()}</span>
                    </div>
                    <div style="font-size: 11px; color: rgba(0, 255, 0, 0.7);">
                        📧 ${user.email} | 📁 ${user.fileCount} files | 💾 ${formatFileSize(user.storageSize)} | 📅 ${new Date(user.createdAt).toLocaleDateString()}
                    </div>
                </div>
                ${user.username !== 'admin' ? `
                <div style="display: flex; gap: 5px;">
                    <button class="btn btn-secondary" onclick="adminResetPassword('${user.username}')" style="padding: 5px 10px; font-size: 10px;">
                        [RESET PWD]
                    </button>
                    <button class="btn btn-secondary" onclick="adminToggleRole('${user.username}', '${user.role}')" style="padding: 5px 10px; font-size: 10px;">
                        [${user.role === 'admin' ? 'DEMOTE' : 'PROMOTE'}]
                    </button>
                    <button class="btn btn-cancel" onclick="adminDeleteUser('${user.username}')" style="padding: 5px 10px; font-size: 10px; border-color: #ff0000; color: #ff0000;">
                        [DELETE]
                    </button>
                </div>
                ` : '<span style="font-size: 10px; color: rgba(0, 255, 0, 0.5);">// PROTECTED ACCOUNT</span>'}
            </div>
        </div>
    `).join('');
}

async function adminDeleteUser(username) {
    if (!confirm(`DELETE USER: ${username}?\n\nThis will remove:\n- User account\n- All user files\n- User settings\n\nThis action cannot be undone!`)) {
        return;
    }

    try {
        // Delete user's files first
        const transaction = fileDB.db.transaction(['files', 'fileData'], 'readwrite');
        const fileStore = transaction.objectStore('files');
        const fileDataStore = transaction.objectStore('fileData');
        const index = fileStore.index('userId');

        const filesRequest = index.getAll(username);
        filesRequest.onsuccess = async () => {
            const files = filesRequest.result;
            
            // Delete all user files
            for (const file of files) {
                fileStore.delete(file.id);
                fileDataStore.delete(file.id);
            }

            // Delete user account
            await authManager.deleteUser(username);
            showStatus(`User ${username} deleted successfully`);
            showAdminPanel(); // Refresh panel
        };
    } catch (error) {
        console.error('Error deleting user:', error);
        showStatus('Error deleting user: ' + error.message, 'error');
    }
}

async function adminToggleRole(username, currentRole) {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    const action = newRole === 'admin' ? 'PROMOTE' : 'DEMOTE';
    
    if (!confirm(`${action} ${username} to ${newRole.toUpperCase()}?`)) {
        return;
    }

    try {
        await authManager.updateUserRole(username, newRole);
        showStatus(`User ${username} ${action.toLowerCase()}d to ${newRole}`);
        showAdminPanel(); // Refresh panel
    } catch (error) {
        console.error('Error updating user role:', error);
        showStatus('Error updating user role: ' + error.message, 'error');
    }
}

async function adminResetPassword(username) {
    const newPassword = prompt(`Enter new password for ${username}:`);
    if (!newPassword) return;

    if (newPassword.length < 4) {
        showStatus('Password must be at least 4 characters', 'error');
        return;
    }

    try {
        await authManager.resetUserPassword(username, newPassword);
        showStatus(`Password reset for ${username}. New password: ${newPassword}`);
    } catch (error) {
        console.error('Error resetting password:', error);
        showStatus('Error resetting password: ' + error.message, 'error');
    }
}

// Initialize app
init();
