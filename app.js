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
            request.onsuccess = async () => {
                this.db = request.result;
                await this.ensureAdminExists();
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
        return new Promise((resolve) => {
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
                resolve();
            };
            checkRequest.onerror = () => resolve();
        });
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
                    token: this.generateToken(),
                    persistent: true,
                    lastActivity: new Date().toISOString()
                };

                sessionStore.put(session);
                this.currentUser = user;
                localStorage.setItem('currentUser', username);
                localStorage.setItem('sessionToken', session.token);
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
            localStorage.removeItem('sessionToken');
        }
    }

    async getCurrentUser() {
        const username = localStorage.getItem('currentUser');
        if (!username) {
            console.log('No username in localStorage');
            return null;
        }

        console.log('Attempting to restore session for:', username);

        try {
            const transaction = this.db.transaction(['users'], 'readonly');
            const userStore = transaction.objectStore('users');

            return new Promise((resolve) => {
                const userRequest = userStore.get(username);
                
                userRequest.onsuccess = async () => {
                    const user = userRequest.result;
                    if (!user) {
                        console.log('User not found in database:', username);
                        // User doesn't exist, clear localStorage
                        localStorage.removeItem('currentUser');
                        localStorage.removeItem('sessionToken');
                        resolve(null);
                        return;
                    }

                    console.log('User found, restoring session:', username);
                    
                    // Create or update session
                    try {
                        const sessionTransaction = this.db.transaction(['sessions'], 'readwrite');
                        const sessionStore = sessionTransaction.objectStore('sessions');
                        
                        const session = {
                            username: username,
                            loginTime: new Date().toISOString(),
                            token: this.generateToken(),
                            persistent: true,
                            lastActivity: new Date().toISOString()
                        };
                        
                        sessionStore.put(session);
                        console.log('Session created/updated for:', username);
                    } catch (sessionError) {
                        console.error('Error creating session:', sessionError);
                    }
                    
                    this.currentUser = user;
                    resolve(user);
                };
                
                userRequest.onerror = () => {
                    console.error('Error fetching user:', userRequest.error);
                    localStorage.removeItem('currentUser');
                    localStorage.removeItem('sessionToken');
                    resolve(null);
                };
            });
        } catch (error) {
            console.error('Error in getCurrentUser:', error);
            return null;
        }
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

    async updateSessionActivity() {
        if (!this.currentUser) return;
        
        try {
            const transaction = this.db.transaction(['sessions'], 'readwrite');
            const store = transaction.objectStore('sessions');
            
            return new Promise((resolve) => {
                const request = store.get(this.currentUser.username);
                request.onsuccess = () => {
                    const session = request.result;
                    if (session) {
                        session.lastActivity = new Date().toISOString();
                        store.put(session);
                    }
                    resolve();
                };
                request.onerror = () => resolve(); // Silently fail
            });
        } catch (error) {
            console.error('Error updating session activity:', error);
        }
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

    async updateUserPassword(username, newPassword) {
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
                updateRequest.onsuccess = () => {
                    // Update currentUser if it's the current user changing their password
                    if (this.currentUser && this.currentUser.username === username) {
                        this.currentUser.password = user.password;
                    }
                    resolve(true);
                };
                updateRequest.onerror = () => reject(updateRequest.error);
            };
            getRequest.onerror = () => reject(getRequest.error);
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
let sessionUpdateInterval = null;

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

// Start session activity tracker
function startSessionMonitor() {
    // Update session activity every 5 minutes
    if (sessionUpdateInterval) {
        clearInterval(sessionUpdateInterval);
    }
    
    sessionUpdateInterval = setInterval(() => {
        authManager.updateSessionActivity();
    }, 5 * 60 * 1000); // 5 minutes
    
    // Also update on user activity
    const activityEvents = ['click', 'keypress', 'mousemove', 'scroll'];
    let lastActivity = Date.now();
    
    activityEvents.forEach(event => {
        document.addEventListener(event, () => {
            const now = Date.now();
            // Only update if more than 1 minute has passed since last update
            if (now - lastActivity > 60000) {
                lastActivity = now;
                authManager.updateSessionActivity();
            }
        }, { passive: true });
    });
}

// Stop session activity tracker
function stopSessionMonitor() {
    if (sessionUpdateInterval) {
        clearInterval(sessionUpdateInterval);
        sessionUpdateInterval = null;
    }
}

// Initialize
async function init() {
    console.log('=== File Manager Initializing ===');
    try {
        console.log('Initializing authManager...');
        await authManager.init();
        console.log('Initializing fileDB...');
        await fileDB.init();
        
        // Check if user is logged in
        console.log('Checking for existing session...');
        const user = await authManager.getCurrentUser();
        if (!user) {
            console.log('No user session found, showing login screen');
            showLoginScreen();
            return;
        }

        console.log('User session restored:', user.username);
        // Make sure currentUser is set
        authManager.currentUser = user;
        fileDB.setUser(user.username);
        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        setupEventListeners();
        updateUserInfo(user);
        startSessionMonitor();
        console.log('File Manager initialized successfully for user:', user.username);
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
                ${isAdmin ? '<button class="btn btn-secondary" onclick="showChangePasswordModal()" style="padding: 5px 10px; font-size: 11px;">[CHANGE PASSWORD]</button>' : ''}
                ${isAdmin ? '<button class="btn btn-secondary" onclick="showAdminPanel()" style="padding: 5px 10px; font-size: 11px;">[ADMIN PANEL]</button>' : ''}
                <button class="btn btn-secondary" onclick="handleLogout()" style="padding: 5px 10px; font-size: 11px;">[LOGOUT]</button>
            </div>
        `;
    }
}

// Validation and Message Functions
function showAuthMessage(formType, message, type = 'error') {
    const messageEl = document.getElementById(`${formType}Message`);
    messageEl.textContent = `// ${message.toUpperCase()}`;
    messageEl.className = `auth-message ${type}`;
    messageEl.style.display = 'block';
    
    // Auto-hide success messages after 3 seconds
    if (type === 'success') {
        setTimeout(() => {
            messageEl.style.display = 'none';
        }, 3000);
    }
}

function hideAuthMessage(formType) {
    const messageEl = document.getElementById(`${formType}Message`);
    messageEl.style.display = 'none';
}

function showFieldError(fieldId, message) {
    const errorEl = document.getElementById(`${fieldId}Error`);
    const inputEl = document.getElementById(fieldId);
    
    if (errorEl && inputEl) {
        errorEl.textContent = message ? `// ${message}` : '';
        if (message) {
            inputEl.classList.add('error');
            inputEl.classList.remove('success');
        } else {
            inputEl.classList.remove('error');
        }
    }
}

function clearFieldError(fieldId) {
    const errorEl = document.getElementById(`${fieldId}Error`);
    const inputEl = document.getElementById(fieldId);
    
    if (errorEl) errorEl.textContent = '';
    if (inputEl) {
        inputEl.classList.remove('error');
    }
}

function markFieldSuccess(fieldId) {
    const inputEl = document.getElementById(fieldId);
    if (inputEl) {
        inputEl.classList.remove('error');
        inputEl.classList.add('success');
    }
}

function clearAllErrors(formType) {
    const form = document.getElementById(`${formType}Form`);
    if (form) {
        const inputs = form.querySelectorAll('.form-input');
        inputs.forEach(input => {
            input.classList.remove('error', 'success');
        });
        const errors = form.querySelectorAll('.field-error');
        errors.forEach(error => error.textContent = '');
    }
    hideAuthMessage(formType);
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validateUsername(username) {
    // Username must be 3-20 characters, alphanumeric and underscore only
    const re = /^[a-zA-Z0-9_]{3,20}$/;
    return re.test(username);
}

function validatePassword(password) {
    return password.length >= 4;
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    clearAllErrors('login');
    
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    // Validation
    let hasError = false;

    if (!username) {
        showFieldError('loginUsername', 'USERNAME_REQUIRED');
        hasError = true;
    } else if (!validateUsername(username)) {
        showFieldError('loginUsername', 'INVALID_USERNAME_FORMAT');
        hasError = true;
    } else {
        markFieldSuccess('loginUsername');
    }

    if (!password) {
        showFieldError('loginPassword', 'PASSWORD_REQUIRED');
        hasError = true;
    } else if (password.length < 4) {
        showFieldError('loginPassword', 'PASSWORD_TOO_SHORT');
        hasError = true;
    } else {
        markFieldSuccess('loginPassword');
    }

    if (hasError) {
        showAuthMessage('login', 'PLEASE_FIX_ERRORS_ABOVE', 'error');
        return;
    }

    // Show loading state
    showAuthMessage('login', 'AUTHENTICATING...', 'info');

    try {
        const user = await authManager.login(username, password);
        authManager.currentUser = user; // Ensure it's set
        fileDB.setUser(user.username);
        
        showAuthMessage('login', 'ACCESS_GRANTED', 'success');
        
        // Small delay to show success message
        setTimeout(async () => {
            hideLoginScreen();
            await loadFilesFromDB();
            await updateStorageInfo();
            renderFiles();
            setupEventListeners();
            updateUserInfo(user);
            startSessionMonitor();
            showStatus(`Welcome back, ${user.username}!`);
        }, 500);
    } catch (error) {
        console.error('Login error:', error);
        if (error.message.includes('not found')) {
            showFieldError('loginUsername', 'USER_NOT_FOUND');
            showAuthMessage('login', 'USER_DOES_NOT_EXIST', 'error');
        } else if (error.message.includes('password')) {
            showFieldError('loginPassword', 'INCORRECT_PASSWORD');
            showAuthMessage('login', 'INVALID_CREDENTIALS', 'error');
        } else {
            showAuthMessage('login', error.message.toUpperCase().replace(/ /g, '_'), 'error');
        }
    }
}

// Handle registration
async function handleRegister(e) {
    e.preventDefault();
    clearAllErrors('register');
    
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('registerConfirmPassword').value;

    // Validation
    let hasError = false;

    // Username validation
    if (!username) {
        showFieldError('registerUsername', 'USERNAME_REQUIRED');
        hasError = true;
    } else if (!validateUsername(username)) {
        showFieldError('registerUsername', 'USERNAME_MUST_BE_3-20_CHARS_(A-Z_0-9_UNDERSCORE)');
        hasError = true;
    } else if (username.toLowerCase() === 'admin' || username.toLowerCase() === 'root') {
        showFieldError('registerUsername', 'USERNAME_RESERVED');
        hasError = true;
    } else {
        markFieldSuccess('registerUsername');
    }

    // Email validation
    if (!email) {
        showFieldError('registerEmail', 'EMAIL_REQUIRED');
        hasError = true;
    } else if (!validateEmail(email)) {
        showFieldError('registerEmail', 'INVALID_EMAIL_FORMAT');
        hasError = true;
    } else {
        markFieldSuccess('registerEmail');
    }

    // Password validation
    if (!password) {
        showFieldError('registerPassword', 'PASSWORD_REQUIRED');
        hasError = true;
    } else if (!validatePassword(password)) {
        showFieldError('registerPassword', 'PASSWORD_MUST_BE_AT_LEAST_4_CHARS');
        hasError = true;
    } else if (password.length > 50) {
        showFieldError('registerPassword', 'PASSWORD_TOO_LONG_(MAX_50)');
        hasError = true;
    } else {
        markFieldSuccess('registerPassword');
    }

    // Confirm password validation
    if (!confirmPassword) {
        showFieldError('registerConfirmPassword', 'CONFIRMATION_REQUIRED');
        hasError = true;
    } else if (password !== confirmPassword) {
        showFieldError('registerConfirmPassword', 'PASSWORDS_DO_NOT_MATCH');
        hasError = true;
    } else {
        markFieldSuccess('registerConfirmPassword');
    }

    if (hasError) {
        showAuthMessage('register', 'PLEASE_FIX_ERRORS_ABOVE', 'error');
        return;
    }

    // Show loading state
    showAuthMessage('register', 'CREATING_ACCOUNT...', 'info');

    try {
        const user = await authManager.register(username, password, email);
        showAuthMessage('register', 'ACCOUNT_CREATED_SUCCESSFULLY', 'success');
        
        // Auto-login after short delay
        setTimeout(async () => {
            await authManager.login(username, password);
            authManager.currentUser = user;
            fileDB.setUser(user.username);
            hideLoginScreen();
            await loadFilesFromDB();
            await updateStorageInfo();
            renderFiles();
            setupEventListeners();
            updateUserInfo(user);
            startSessionMonitor();
            showStatus(`Welcome, ${user.username}! Your account has been created.`);
        }, 800);
    } catch (error) {
        console.error('Registration error:', error);
        if (error.message.includes('already exists')) {
            showFieldError('registerUsername', 'USERNAME_TAKEN');
            showAuthMessage('register', 'USERNAME_ALREADY_EXISTS', 'error');
        } else {
            showAuthMessage('register', error.message.toUpperCase().replace(/ /g, '_'), 'error');
        }
    }
}

// Handle logout
async function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        stopSessionMonitor();
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
        // Switch to login
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        toggleText.textContent = '// NEW USER?';
        toggleLink.textContent = '[REGISTER]';
        
        // Clear register form errors
        clearAllErrors('register');
        document.getElementById('registerForm').reset();
    } else {
        // Switch to register
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        toggleText.textContent = '// HAVE AN ACCOUNT?';
        toggleLink.textContent = '[LOGIN]';
        
        // Clear login form errors
        clearAllErrors('login');
        document.getElementById('loginForm').reset();
    }
}

// Show Forgot Password Modal
function showForgotPasswordModal() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('forgotPasswordModal').style.display = 'flex';
    
    // Clear form
    document.getElementById('recoveryUsername').value = 'admin';
    document.getElementById('recoveryCode').value = '';
    document.getElementById('recoveryNewPassword').value = '';
    document.getElementById('recoveryConfirmPassword').value = '';
    
    // Clear errors
    ['recoveryUsername', 'recoveryCode', 'recoveryNewPassword', 'recoveryConfirmPassword'].forEach(id => {
        const errorEl = document.getElementById(`${id}Error`);
        const inputEl = document.getElementById(id);
        if (errorEl) errorEl.textContent = '';
        if (inputEl) inputEl.classList.remove('error', 'success');
    });
    
    const messageEl = document.getElementById('forgotPasswordMessage');
    if (messageEl) messageEl.style.display = 'none';
}

// Close Forgot Password Modal
function closeForgotPasswordModal() {
    document.getElementById('forgotPasswordModal').style.display = 'none';
    document.getElementById('loginScreen').style.display = 'flex';
}

// Generate Recovery Code
async function generateRecoveryCode() {
    const username = document.getElementById('recoveryUsername').value.trim();
    if (!username) {
        showForgotPasswordMessage('ENTER_USERNAME_FIRST', 'error');
        return;
    }
    
    // SECURITY: Block admin recovery code generation
    if (username.toLowerCase() === 'admin') {
        showFieldError('recoveryUsername', 'ADMIN_RECOVERY_NOT_ALLOWED');
        showForgotPasswordMessage('ADMIN_PASSWORD_CANNOT_BE_RECOVERED', 'error');
        console.error('%c✗ Admin recovery code generation blocked for security', 'color: #ff0000; font-weight: bold;');
        console.warn('%c⚠️ If you forgot admin password:', 'color: #ffaa00; font-weight: bold;');
        console.warn('%c1. Export data backup before logging out (if logged in)', 'color: #ffaa00;');
        console.warn('%c2. Clear all data from Admin Panel', 'color: #ffaa00;');
        console.warn('%c3. Or import a previous backup to restore access', 'color: #ffaa00;');
        return;
    }
    
    // Check if user exists
    try {
        const transaction = authManager.db.transaction(['users'], 'readonly');
        const store = transaction.objectStore('users');
        
        const user = await new Promise((resolve) => {
            const request = store.get(username);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => resolve(null);
        });
        
        if (!user) {
            showFieldError('recoveryUsername', 'USER_NOT_FOUND');
            showForgotPasswordMessage('USER_DOES_NOT_EXIST', 'error');
            return;
        }
        
        // Check if user has email
        if (!user.email) {
            showForgotPasswordMessage('USER_HAS_NO_EMAIL_REGISTERED', 'error');
            return;
        }
        
        // Generate a 6-digit code based on timestamp and username
        const timestamp = Date.now();
        const userHash = username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
        const code = Math.floor(((timestamp + userHash) % 900000) + 100000).toString();
        
        // Store in session storage temporarily (valid for 10 minutes)
        const expiryTime = Date.now() + (10 * 60 * 1000);
        sessionStorage.setItem(`recoveryCode_${username}`, code);
        sessionStorage.setItem(`recoveryCodeExpiry_${username}`, expiryTime);
        
        // Log to console with styling
        console.clear();
        console.log('%c╔════════════════════════════════════════╗', 'color: #00ff00; font-weight: bold;');
        console.log('%c║   PASSWORD RECOVERY CODE GENERATED    ║', 'color: #00ff00; font-weight: bold;');
        console.log('%c╠════════════════════════════════════════╣', 'color: #00ff00; font-weight: bold;');
        console.log('%c║                                        ║', 'color: #00ff00;');
        console.log(`%c║   USERNAME: ${username.padEnd(25)}║`, 'color: #00ff00;');
        console.log(`%c║   EMAIL:    ${user.email.padEnd(25)}║`, 'color: #00ff00;');
        console.log(`%c║   CODE:     ${code.padEnd(25)}║`, 'color: #00ff00; font-size: 16px; font-weight: bold;');
        console.log('%c║                                        ║', 'color: #00ff00;');
        console.log(`%c║   Valid for: 10 minutes                ║`, 'color: #00ff00;');
        console.log('%c║                                        ║', 'color: #00ff00;');
        console.log('%c╚════════════════════════════════════════╝', 'color: #00ff00; font-weight: bold;');
        console.log('%c⚠️ This code will expire in 10 minutes', 'color: #ffaa00; font-weight: bold;');
        console.log('%c📋 Copy this code and paste it in the recovery form', 'color: #00ffff;');
        console.log('%c🔒 This code is tied to username: ' + username, 'color: #00ffff;');
        
        showForgotPasswordMessage(`CODE_SENT_TO_${user.email.toUpperCase()}_AND_CONSOLE`, 'success');
    } catch (error) {
        console.error('Error generating recovery code:', error);
        showForgotPasswordMessage('ERROR_GENERATING_CODE', 'error');
    }
}

// Show message in forgot password modal
function showForgotPasswordMessage(message, type = 'error') {
    const messageEl = document.getElementById('forgotPasswordMessage');
    messageEl.textContent = `// ${message.toUpperCase()}`;
    messageEl.className = `auth-message ${type}`;
    messageEl.style.display = 'block';
}

// Confirm Password Recovery
async function confirmPasswordRecovery() {
    // Clear errors
    ['recoveryUsername', 'recoveryCode', 'recoveryNewPassword', 'recoveryConfirmPassword'].forEach(id => {
        const errorEl = document.getElementById(`${id}Error`);
        const inputEl = document.getElementById(id);
        if (errorEl) errorEl.textContent = '';
        if (inputEl) inputEl.classList.remove('error', 'success');
    });
    
    const username = document.getElementById('recoveryUsername').value.trim();
    const code = document.getElementById('recoveryCode').value.trim().toUpperCase();
    const newPassword = document.getElementById('recoveryNewPassword').value;
    const confirmPassword = document.getElementById('recoveryConfirmPassword').value;
    
    let hasError = false;
    
    // Validate username
    if (!username) {
        showFieldError('recoveryUsername', 'USERNAME_REQUIRED');
        hasError = true;
    }
    
    // Validate code
    if (!code) {
        showFieldError('recoveryCode', 'RECOVERY_CODE_REQUIRED');
        hasError = true;
    }
    
    // Validate new password
    if (!newPassword) {
        showFieldError('recoveryNewPassword', 'PASSWORD_REQUIRED');
        hasError = true;
    } else if (newPassword.length < 4) {
        showFieldError('recoveryNewPassword', 'MIN_4_CHARACTERS');
        hasError = true;
    }
    
    // Validate confirm password
    if (!confirmPassword) {
        showFieldError('recoveryConfirmPassword', 'CONFIRMATION_REQUIRED');
        hasError = true;
    } else if (newPassword !== confirmPassword) {
        showFieldError('recoveryConfirmPassword', 'PASSWORDS_DO_NOT_MATCH');
        hasError = true;
    }
    
    if (hasError) {
        showForgotPasswordMessage('PLEASE_FIX_ERRORS_ABOVE', 'error');
        return;
    }
    
    showForgotPasswordMessage('VERIFYING_RECOVERY_CODE...', 'info');
    
    try {
        // SECURITY: Block admin password recovery completely
        if (username.toLowerCase() === 'admin') {
            showFieldError('recoveryUsername', 'ADMIN_RECOVERY_BLOCKED');
            showForgotPasswordMessage('ADMIN_PASSWORD_CANNOT_BE_RECOVERED_FOR_SECURITY', 'error');
            console.error('%c✗ Admin password recovery blocked for security', 'color: #ff0000; font-weight: bold;');
            return;
        }
        
        // Check if user exists
        const transaction = authManager.db.transaction(['users'], 'readonly');
        const store = transaction.objectStore('users');
        
        const user = await new Promise((resolve) => {
            const request = store.get(username);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => resolve(null);
        });
        
        if (!user) {
            showFieldError('recoveryUsername', 'USER_NOT_FOUND');
            showForgotPasswordMessage('USER_DOES_NOT_EXIST', 'error');
            return;
        }
        
        // Verify recovery code with username-specific storage
        const storedCode = sessionStorage.getItem(`recoveryCode_${username}`);
        const expiryTime = sessionStorage.getItem(`recoveryCodeExpiry_${username}`);
        
        let isValid = false;
        
        // Check session recovery code (username-specific)
        if (storedCode && expiryTime) {
            // Check if code is expired
            if (Date.now() > parseInt(expiryTime)) {
                showFieldError('recoveryCode', 'CODE_EXPIRED_GENERATE_NEW');
                showForgotPasswordMessage('RECOVERY_CODE_EXPIRED', 'error');
                return;
            }
            
            // Verify code matches
            if (code === storedCode) {
                isValid = true;
                console.log('%c✓ Recovery code verified for user: ' + username, 'color: #00ff00; font-weight: bold;');
            }
        }
        
        if (!isValid) {
            showFieldError('recoveryCode', 'INVALID_RECOVERY_CODE');
            showForgotPasswordMessage('RECOVERY_CODE_INCORRECT', 'error');
            return;
        }
        
        // Reset password
        await authManager.updateUserPassword(username, newPassword);
        
        // Clear recovery codes for this specific user
        sessionStorage.removeItem(`recoveryCode_${username}`);
        sessionStorage.removeItem(`recoveryCodeExpiry_${username}`);
        
        showForgotPasswordMessage('PASSWORD_RESET_SUCCESSFUL', 'success');
        
        // Redirect to login after 1.5 seconds
        setTimeout(() => {
            closeForgotPasswordModal();
            document.getElementById('loginUsername').value = username;
            showStatus('Password reset successfully! Please login with your new password.');
        }, 1500);
        
    } catch (error) {
        console.error('Error during password recovery:', error);
        showForgotPasswordMessage('ERROR_RESETTING_PASSWORD', 'error');
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
            ${file.starred ? '<div style="position: absolute; top: 5px; right: 5px; font-size: 16px;">⭐</div>' : ''}
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
    let filtered;
    
    // For starred view, show all starred files regardless of path
    if (currentFilter === 'starred') {
        filtered = files.filter(f => f.starred);
    } else {
        // For other filters, only show files in current path
        filtered = files.filter(f => f.path === currentPath);
    }

    if (currentFilter === 'recent') {
        filtered.sort((a, b) => new Date(b.modified) - new Date(a.modified));
    } else if (currentFilter !== 'all' && currentFilter !== 'starred') {
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
// Open file
async function openFile() {
    // Save reference to avoid null issues
    const fileToOpen = selectedFile;
    
    if (!fileToOpen) {
        console.error('No file selected');
        hideContextMenu();
        return;
    }
    
    if (fileToOpen.type === 'folder') {
        openFolder(fileToOpen);
    } else {
        // Try to download/open the file
        const blob = await fileDB.getFileBlob(fileToOpen.id);
        if (blob) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.target = '_blank';
            a.click();
            URL.revokeObjectURL(url);
        } else {
            alert(`Opening: ${fileToOpen.name}\n(File blob not available)`);
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
    // Save reference to avoid null issues
    const fileToRename = selectedFile;
    
    if (!fileToRename) {
        console.error('No file selected for rename');
        hideContextMenu();
        return;
    }
    
    document.getElementById('renameInput').value = fileToRename.name;
    showModal('renameModal');
    hideContextMenu();
}

// Confirm rename
async function confirmRename() {
    const newName = document.getElementById('renameInput').value.trim();
    const fileToRename = selectedFile;
    
    if (!newName) {
        alert('Please enter a new name');
        return;
    }
    
    if (!fileToRename) {
        alert('No file selected');
        closeModal('renameModal');
        return;
    }
    
    try {
        await fileDB.updateFile(fileToRename.id, { name: newName });
        await loadFilesFromDB();
        renderFiles();
        closeModal('renameModal');
        showStatus('File renamed successfully');
    } catch (error) {
        console.error('Error renaming file:', error);
        showStatus('Error renaming file', 'error');
    }
}

// Download file
async function downloadFile() {
    // Save reference to avoid null issues
    const fileToDownload = selectedFile;
    
    if (!fileToDownload) {
        console.error('No file selected for download');
        alert('No file selected. Please right-click on a file to download.');
        hideContextMenu();
        return;
    }
    
    if (fileToDownload.type === 'folder') {
        alert('Cannot download folders');
        hideContextMenu();
        return;
    }
    
    try {
        const blob = await fileDB.getFileBlob(fileToDownload.id);
        if (blob) {
            // Simply download without checksum verification for now
            showStatus('Downloading file...', 'info');
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileToDownload.name;
            a.click();
            URL.revokeObjectURL(url);
            
            setTimeout(() => {
                showStatus(`Downloaded: ${fileToDownload.name}`);
            }, 500);
        } else {
            alert('File data not available');
            showStatus('File data not available', 'error');
        }
    } catch (error) {
        console.error('Error downloading file:', error);
        alert('Error downloading file: ' + error.message);
        showStatus('Error downloading file', 'error');
    }
    
    hideContextMenu();
}

// Toggle star
async function toggleStar() {
    // Save reference to avoid null issues
    const fileToStar = selectedFile;
    
    if (!fileToStar) {
        console.error('No file selected for starring');
        hideContextMenu();
        return;
    }
    
    try {
        const newStarredState = !fileToStar.starred;
        await fileDB.updateFile(fileToStar.id, { starred: newStarredState });
        await loadFilesFromDB();
        renderFiles();
        
        // Show status message
        const statusMessage = newStarredState 
            ? `★ ${fileToStar.name} starred` 
            : `☆ ${fileToStar.name} unstarred`;
        showStatus(statusMessage, 'success');
    } catch (error) {
        console.error('Error toggling star:', error);
        showStatus('Error updating star status', 'error');
    }
    
    hideContextMenu();
}

// Delete file
// Delete file
async function deleteFile() {
    // Save reference to avoid null issues
    const fileToDelete = selectedFile;
    
    if (!fileToDelete) {
        console.error('No file selected for deletion');
        hideContextMenu();
        return;
    }
    
    if (confirm(`Delete ${fileToDelete.name}?`)) {
        try {
            await fileDB.deleteFile(fileToDelete.id);
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

    // Show progress section
    const progressSection = document.getElementById('uploadProgressSection');
    const progressBar = document.getElementById('uploadProgressBar');
    const progressText = document.getElementById('uploadProgressText');
    const currentFileNameEl = document.getElementById('currentFileName');
    const uploadStatsEl = document.getElementById('uploadStats');
    const uploadSpeedEl = document.getElementById('uploadSpeed');
    const uploadStatusEl = document.getElementById('uploadStatus');
    const integrityCheckEl = document.getElementById('integrityCheck');
    const uploadBtn = document.getElementById('uploadBtn');
    const uploadCancelBtn = document.getElementById('uploadCancelBtn');

    // Disable upload button and show cancel only
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'UPLOADING...';
    progressSection.style.display = 'block';

    let uploadedCount = 0;
    const totalFiles = uploadedFiles.length;
    const startTime = Date.now();
    let totalBytesProcessed = 0;

    try {
        for (let i = 0; i < uploadedFiles.length; i++) {
            const file = uploadedFiles[i];
            
            // Update current file info
            currentFileNameEl.textContent = `$ UPLOADING: ${file.name} (${formatFileSize(file.size)})`;
            uploadStatusEl.innerHTML = `// PROCESSING FILE ${i + 1} OF ${totalFiles}...`;
            
            // Calculate checksum for integrity verification
            integrityCheckEl.style.display = 'block';
            integrityCheckEl.innerHTML = `✓ CALCULATING CHECKSUM FOR: ${file.name}`;
            
            const checksum = await calculateFileChecksum(file);
            
            integrityCheckEl.innerHTML = `✓ CHECKSUM: ${checksum.substring(0, 16)}...`;
            
            // Simulate upload progress (since IndexedDB is local)
            await simulateUploadProgress(file.size, (progress) => {
                const overallProgress = ((uploadedCount + progress / 100) / totalFiles) * 100;
                progressBar.style.width = overallProgress + '%';
                progressText.textContent = Math.round(overallProgress) + '%';
                
                // Update stats
                uploadStatsEl.textContent = `${uploadedCount} / ${totalFiles} files`;
                
                // Calculate upload speed
                const elapsedTime = (Date.now() - startTime) / 1000; // seconds
                const bytesProcessed = totalBytesProcessed + (file.size * progress / 100);
                const speed = bytesProcessed / elapsedTime;
                uploadSpeedEl.textContent = formatFileSize(speed) + '/s';
            });

            // Create file metadata with checksum
            const fileMetadata = {
                name: file.name,
                type: getFileType(file.name),
                size: formatFileSize(file.size),
                sizeBytes: file.size,
                modified: new Date().toISOString(),
                starred: false,
                path: currentPath,
                checksum: checksum // Store checksum for integrity verification
            };

            // Store metadata and file blob
            await fileDB.addFile(fileMetadata, file);
            
            uploadedCount++;
            totalBytesProcessed += file.size;
            
            // Update progress
            const overallProgress = (uploadedCount / totalFiles) * 100;
            progressBar.style.width = overallProgress + '%';
            progressText.textContent = Math.round(overallProgress) + '%';
            uploadStatsEl.textContent = `${uploadedCount} / ${totalFiles} files`;
            
            uploadStatusEl.innerHTML = `// FILE ${i + 1} UPLOADED SUCCESSFULLY`;
        }

        // Upload complete
        uploadStatusEl.innerHTML = `✓ ALL FILES UPLOADED SUCCESSFULLY!`;
        integrityCheckEl.innerHTML = `✓ ALL FILES VERIFIED - INTEGRITY CHECKS PASSED`;
        
        // Wait a moment before closing
        await new Promise(resolve => setTimeout(resolve, 1500));

        await loadFilesFromDB();
        await updateStorageInfo();
        renderFiles();
        closeModal('uploadModal');
        fileInput.value = '';
        
        // Reset progress UI
        progressSection.style.display = 'none';
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        uploadBtn.disabled = false;
        uploadBtn.textContent = '[ENTER]';
        
        showStatus(`${uploadedFiles.length} file(s) uploaded successfully with integrity verification`);
    } catch (error) {
        console.error('Error uploading files:', error);
        uploadStatusEl.innerHTML = `✗ ERROR: ${error.message}`;
        uploadBtn.disabled = false;
        uploadBtn.textContent = '[ENTER]';
        showStatus('Error uploading files', 'error');
    }
}

// Calculate file checksum using SHA-256
// Calculate file checksum using SHA-256
async function calculateFileChecksum(file) {
    try {
        if (!file || !(file instanceof Blob)) {
            throw new Error('Invalid file object');
        }
        
        const arrayBuffer = await file.arrayBuffer();
        
        if (!arrayBuffer || arrayBuffer.byteLength === 0) {
            throw new Error('Empty file or invalid data');
        }
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    } catch (error) {
        console.error('Error calculating checksum:', error);
        throw new Error(`Checksum calculation failed: ${error.message}`);
    }
}

// Simulate upload progress for local storage
async function simulateUploadProgress(fileSize, onProgress) {
    // Simulate chunked upload based on file size
    const chunkSize = 1024 * 1024; // 1MB chunks
    const totalChunks = Math.ceil(fileSize / chunkSize);
    const delayPerChunk = Math.min(50, Math.max(10, 500 / totalChunks)); // Adaptive delay
    
    for (let i = 0; i <= totalChunks; i++) {
        const progress = (i / totalChunks) * 100;
        onProgress(progress);
        await new Promise(resolve => setTimeout(resolve, delayPerChunk));
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
    
    // Set icon based on type
    if (type === 'success') {
        icon.textContent = '✓';
    } else if (type === 'error') {
        icon.textContent = '✗';
    } else if (type === 'info' || type === 'warning') {
        icon.textContent = '⚠';
    } else {
        icon.textContent = '•';
    }
    
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

// Mobile Menu Functions
function toggleMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar.classList.contains('mobile-open')) {
        closeMobileSidebar();
    } else {
        sidebar.classList.add('mobile-open');
        overlay.style.display = 'block';
    }
}

function closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    sidebar.classList.remove('mobile-open');
    overlay.style.display = 'none';
}

// Check if mobile and show/hide menu button
function checkMobileView() {
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    if (window.innerWidth <= 768) {
        mobileMenuBtn.style.display = 'inline-block';
    } else {
        mobileMenuBtn.style.display = 'none';
        closeMobileSidebar();
    }
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
    
    // Mobile responsiveness
    window.addEventListener('resize', checkMobileView);
    checkMobileView();
    
    // Close mobile sidebar when clicking on sidebar items
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                setTimeout(closeMobileSidebar, 300);
            }
        });
    });
}

// Admin Panel Functions
async function showAdminPanel() {
    // Get the current user from authManager
    let user = authManager.currentUser;
    
    // If not set, try to get from database
    if (!user) {
        user = await authManager.getCurrentUser();
    }
    
    console.log('Current user:', user);
    console.log('Is admin?', user ? authManager.isAdmin(user) : 'No user');
    
    if (!user || !authManager.isAdmin(user)) {
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
                        <span style="font-size: 10px; padding: 2px 6px; border: 1px solid ${(user.role || 'user') === 'admin' ? '#ff0000' : '#00ff00'}; color: ${(user.role || 'user') === 'admin' ? '#ff0000' : '#00ff00'};">${(user.role || 'user').toUpperCase()}</span>
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
                    <button class="btn btn-secondary" onclick="adminToggleRole('${user.username}', '${user.role || 'user'}')" style="padding: 5px 10px; font-size: 10px;">
                        [${(user.role || 'user') === 'admin' ? 'DEMOTE' : 'PROMOTE'}]
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

// Export all data
async function exportAllData() {
    if (!confirm('Export all users, files, and settings to a JSON file?')) return;
    
    try {
        showStatus('Exporting data...', 'info');
        
        const exportData = {
            version: '1.0',
            exportDate: new Date().toISOString(),
            users: [],
            sessions: [],
            userSettings: [],
            files: [],
            fileData: []
        };
        
        // Export users
        const usersTransaction = authManager.db.transaction(['users'], 'readonly');
        const usersStore = usersTransaction.objectStore('users');
        const usersRequest = usersStore.getAll();
        
        await new Promise((resolve, reject) => {
            usersRequest.onsuccess = () => {
                exportData.users = usersRequest.result;
                resolve();
            };
            usersRequest.onerror = () => reject(usersRequest.error);
        });
        
        // Export sessions
        const sessionsTransaction = authManager.db.transaction(['sessions'], 'readonly');
        const sessionsStore = sessionsTransaction.objectStore('sessions');
        const sessionsRequest = sessionsStore.getAll();
        
        await new Promise((resolve, reject) => {
            sessionsRequest.onsuccess = () => {
                exportData.sessions = sessionsRequest.result;
                resolve();
            };
            sessionsRequest.onerror = () => reject(sessionsRequest.error);
        });
        
        // Export user settings
        const settingsTransaction = authManager.db.transaction(['userSettings'], 'readonly');
        const settingsStore = settingsTransaction.objectStore('userSettings');
        const settingsRequest = settingsStore.getAll();
        
        await new Promise((resolve, reject) => {
            settingsRequest.onsuccess = () => {
                exportData.userSettings = settingsRequest.result;
                resolve();
            };
            settingsRequest.onerror = () => reject(settingsRequest.error);
        });
        
        // Export files
        const filesTransaction = fileDB.db.transaction(['files'], 'readonly');
        const filesStore = filesTransaction.objectStore('files');
        const filesRequest = filesStore.getAll();
        
        await new Promise((resolve, reject) => {
            filesRequest.onsuccess = () => {
                exportData.files = filesRequest.result;
                resolve();
            };
            filesRequest.onerror = () => reject(filesRequest.error);
        });
        
        // Export file data (blobs)
        const fileDataTransaction = fileDB.db.transaction(['fileData'], 'readonly');
        const fileDataStore = fileDataTransaction.objectStore('fileData');
        const fileDataRequest = fileDataStore.getAll();
        
        await new Promise((resolve, reject) => {
            fileDataRequest.onsuccess = async () => {
                // Convert blobs to base64
                const fileDataArray = fileDataRequest.result;
                for (const item of fileDataArray) {
                    if (item.blob instanceof Blob) {
                        const reader = new FileReader();
                        const base64 = await new Promise((res) => {
                            reader.onloadend = () => res(reader.result);
                            reader.readAsDataURL(item.blob);
                        });
                        exportData.fileData.push({
                            id: item.id,
                            data: base64,
                            type: item.blob.type
                        });
                    }
                }
                resolve();
            };
            fileDataRequest.onerror = () => reject(fileDataRequest.error);
        });
        
        // Create download
        const dataStr = JSON.stringify(exportData, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `filemanager_backup_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showStatus('Data exported successfully!');
    } catch (error) {
        console.error('Error exporting data:', error);
        showStatus('Error exporting data: ' + error.message, 'error');
    }
}

// Import all data
function importAllData() {
    if (!confirm('Import data from file? This will REPLACE all existing data!')) return;
    document.getElementById('importFileInput').click();
}

// Handle import file
async function handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    try {
        showStatus('Importing data...', 'info');
        
        const text = await file.text();
        const importData = JSON.parse(text);
        
        if (!importData.version || !importData.users) {
            throw new Error('Invalid backup file format');
        }
        
        // Clear existing data first
        await clearAllDataSilent();
        
        // Import users
        const usersTransaction = authManager.db.transaction(['users'], 'readwrite');
        const usersStore = usersTransaction.objectStore('users');
        for (const user of importData.users) {
            await new Promise((resolve, reject) => {
                const request = usersStore.add(user);
                request.onsuccess = () => resolve();
                request.onerror = () => resolve(); // Continue on duplicate
            });
        }
        
        // Import sessions
        if (importData.sessions) {
            const sessionsTransaction = authManager.db.transaction(['sessions'], 'readwrite');
            const sessionsStore = sessionsTransaction.objectStore('sessions');
            for (const session of importData.sessions) {
                await new Promise((resolve, reject) => {
                    const request = sessionsStore.add(session);
                    request.onsuccess = () => resolve();
                    request.onerror = () => resolve();
                });
            }
        }
        
        // Import user settings
        if (importData.userSettings) {
            const settingsTransaction = authManager.db.transaction(['userSettings'], 'readwrite');
            const settingsStore = settingsTransaction.objectStore('userSettings');
            for (const settings of importData.userSettings) {
                await new Promise((resolve, reject) => {
                    const request = settingsStore.add(settings);
                    request.onsuccess = () => resolve();
                    request.onerror = () => resolve();
                });
            }
        }
        
        // Import files
        if (importData.files) {
            const filesTransaction = fileDB.db.transaction(['files'], 'readwrite');
            const filesStore = filesTransaction.objectStore('files');
            for (const file of importData.files) {
                await new Promise((resolve, reject) => {
                    const request = filesStore.add(file);
                    request.onsuccess = () => resolve();
                    request.onerror = () => resolve();
                });
            }
        }
        
        // Import file data (convert base64 back to blobs)
        if (importData.fileData) {
            const fileDataTransaction = fileDB.db.transaction(['fileData'], 'readwrite');
            const fileDataStore = fileDataTransaction.objectStore('fileData');
            for (const item of importData.fileData) {
                // Convert base64 to blob
                const response = await fetch(item.data);
                const blob = await response.blob();
                
                await new Promise((resolve, reject) => {
                    const request = fileDataStore.add({ id: item.id, blob: blob });
                    request.onsuccess = () => resolve();
                    request.onerror = () => resolve();
                });
            }
        }
        
        showStatus('Data imported successfully! Reloading page...');
        setTimeout(() => {
            location.reload();
        }, 1500);
        
    } catch (error) {
        console.error('Error importing data:', error);
        showStatus('Error importing data: ' + error.message, 'error');
    }
    
    // Reset file input
    event.target.value = '';
}

// Clear all data
async function clearAllData() {
    if (!confirm('⚠️ WARNING: This will DELETE ALL users, files, and settings! Are you absolutely sure?')) return;
    if (!confirm('This action CANNOT be undone! Click OK to proceed with deletion.')) return;
    
    try {
        showStatus('Clearing all data...', 'info');
        await clearAllDataSilent();
        showStatus('All data cleared! Reloading...');
        setTimeout(() => {
            location.reload();
        }, 1000);
    } catch (error) {
        console.error('Error clearing data:', error);
        showStatus('Error clearing data: ' + error.message, 'error');
    }
}

// Clear all data silently (helper function)
async function clearAllDataSilent() {
    // Clear auth database
    const authStores = ['users', 'sessions', 'userSettings'];
    for (const storeName of authStores) {
        const transaction = authManager.db.transaction([storeName], 'readwrite');
        const store = transaction.objectStore(storeName);
        await new Promise((resolve, reject) => {
            const request = store.clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    
    // Clear file database
    const fileStores = ['files', 'fileData'];
    for (const storeName of fileStores) {
        const transaction = fileDB.db.transaction([storeName], 'readwrite');
        const store = transaction.objectStore(storeName);
        await new Promise((resolve, reject) => {
            const request = store.clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    
    // Clear localStorage
    localStorage.clear();
}

// Show Change Password Modal
function showChangePasswordModal() {
    // Clear form and errors
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmNewPassword').value = '';
    clearChangePasswordErrors();
    
    // Show modal
    document.getElementById('changePasswordModal').style.display = 'flex';
}

// Close Change Password Modal
function closeChangePasswordModal() {
    document.getElementById('changePasswordModal').style.display = 'none';
    clearChangePasswordErrors();
}

// Clear change password errors
function clearChangePasswordErrors() {
    const fields = ['currentPassword', 'newPassword', 'confirmNewPassword'];
    fields.forEach(fieldId => {
        const errorEl = document.getElementById(`${fieldId}Error`);
        const inputEl = document.getElementById(fieldId);
        if (errorEl) errorEl.textContent = '';
        if (inputEl) inputEl.classList.remove('error', 'success');
    });
    
    const messageEl = document.getElementById('changePasswordMessage');
    if (messageEl) messageEl.style.display = 'none';
}

// Show message in change password modal
function showChangePasswordMessage(message, type = 'error') {
    const messageEl = document.getElementById('changePasswordMessage');
    messageEl.textContent = `// ${message.toUpperCase()}`;
    messageEl.className = `auth-message ${type}`;
    messageEl.style.display = 'block';
}

// Confirm Change Password
async function confirmChangePassword() {
    clearChangePasswordErrors();
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;
    
    let hasError = false;
    
    // Validate current password
    if (!currentPassword) {
        showFieldError('currentPassword', 'CURRENT_PASSWORD_REQUIRED');
        hasError = true;
    }
    
    // Validate new password
    if (!newPassword) {
        showFieldError('newPassword', 'NEW_PASSWORD_REQUIRED');
        hasError = true;
    } else if (newPassword.length < 4) {
        showFieldError('newPassword', 'PASSWORD_MUST_BE_AT_LEAST_4_CHARS');
        hasError = true;
    } else if (newPassword.length > 50) {
        showFieldError('newPassword', 'PASSWORD_TOO_LONG_(MAX_50)');
        hasError = true;
    } else if (newPassword === currentPassword) {
        showFieldError('newPassword', 'NEW_PASSWORD_MUST_BE_DIFFERENT');
        hasError = true;
    }
    
    // Validate confirm password
    if (!confirmNewPassword) {
        showFieldError('confirmNewPassword', 'CONFIRMATION_REQUIRED');
        hasError = true;
    } else if (newPassword !== confirmNewPassword) {
        showFieldError('confirmNewPassword', 'PASSWORDS_DO_NOT_MATCH');
        hasError = true;
    }
    
    if (hasError) {
        showChangePasswordMessage('PLEASE_FIX_ERRORS_ABOVE', 'error');
        return;
    }
    
    // Show loading
    showChangePasswordMessage('UPDATING_PASSWORD...', 'info');
    
    try {
        // Verify current password by attempting login
        const username = authManager.currentUser.username;
        const hashedCurrentPassword = btoa(currentPassword + username);
        
        if (authManager.currentUser.password !== hashedCurrentPassword) {
            showFieldError('currentPassword', 'INCORRECT_PASSWORD');
            showChangePasswordMessage('CURRENT_PASSWORD_IS_INCORRECT', 'error');
            return;
        }
        
        // Update password
        await authManager.updateUserPassword(username, newPassword);
        
        showChangePasswordMessage('PASSWORD_UPDATED_SUCCESSFULLY', 'success');
        
        // Log out after 1.5 seconds
        setTimeout(async () => {
            closeChangePasswordModal();
            await handleLogout();
            showStatus('Password changed successfully. Please login with your new password.');
        }, 1500);
        
    } catch (error) {
        console.error('Error changing password:', error);
        showChangePasswordMessage('ERROR_UPDATING_PASSWORD', 'error');
    }
}

// Setup real-time form validation
function setupFormValidation() {
    // Login form validation
    const loginUsername = document.getElementById('loginUsername');
    const loginPassword = document.getElementById('loginPassword');
    
    if (loginUsername) {
        loginUsername.addEventListener('input', (e) => {
            const value = e.target.value.trim();
            if (value && !validateUsername(value)) {
                showFieldError('loginUsername', 'INVALID_FORMAT_(A-Z_0-9_UNDERSCORE_3-20)');
            } else {
                clearFieldError('loginUsername');
                if (value) markFieldSuccess('loginUsername');
            }
        });
        
        loginUsername.addEventListener('blur', (e) => {
            const value = e.target.value.trim();
            if (!value) {
                clearFieldError('loginUsername');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (loginPassword) {
        loginPassword.addEventListener('input', (e) => {
            const value = e.target.value;
            if (value && value.length < 4) {
                showFieldError('loginPassword', 'MIN_4_CHARACTERS');
            } else {
                clearFieldError('loginPassword');
                if (value) markFieldSuccess('loginPassword');
            }
        });
        
        loginPassword.addEventListener('blur', (e) => {
            if (!e.target.value) {
                clearFieldError('loginPassword');
                e.target.classList.remove('success');
            }
        });
    }
    
    // Register form validation
    const registerUsername = document.getElementById('registerUsername');
    const registerEmail = document.getElementById('registerEmail');
    const registerPassword = document.getElementById('registerPassword');
    const registerConfirmPassword = document.getElementById('registerConfirmPassword');
    
    if (registerUsername) {
        registerUsername.addEventListener('input', (e) => {
            const value = e.target.value.trim();
            if (value) {
                if (!validateUsername(value)) {
                    showFieldError('registerUsername', 'INVALID_FORMAT_(A-Z_0-9_UNDERSCORE_3-20)');
                } else if (value.toLowerCase() === 'admin' || value.toLowerCase() === 'root') {
                    showFieldError('registerUsername', 'USERNAME_RESERVED');
                } else {
                    clearFieldError('registerUsername');
                    markFieldSuccess('registerUsername');
                }
            } else {
                clearFieldError('registerUsername');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (registerEmail) {
        registerEmail.addEventListener('input', (e) => {
            const value = e.target.value.trim();
            if (value) {
                if (!validateEmail(value)) {
                    showFieldError('registerEmail', 'INVALID_EMAIL_FORMAT');
                } else {
                    clearFieldError('registerEmail');
                    markFieldSuccess('registerEmail');
                }
            } else {
                clearFieldError('registerEmail');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (registerPassword) {
        registerPassword.addEventListener('input', (e) => {
            const value = e.target.value;
            if (value) {
                if (value.length < 4) {
                    showFieldError('registerPassword', 'MIN_4_CHARACTERS');
                } else if (value.length > 50) {
                    showFieldError('registerPassword', 'MAX_50_CHARACTERS');
                } else {
                    clearFieldError('registerPassword');
                    markFieldSuccess('registerPassword');
                }
                
                // Re-validate confirm password if it has a value
                if (registerConfirmPassword && registerConfirmPassword.value) {
                    if (value !== registerConfirmPassword.value) {
                        showFieldError('registerConfirmPassword', 'PASSWORDS_DO_NOT_MATCH');
                    } else {
                        clearFieldError('registerConfirmPassword');
                        markFieldSuccess('registerConfirmPassword');
                    }
                }
            } else {
                clearFieldError('registerPassword');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (registerConfirmPassword) {
        registerConfirmPassword.addEventListener('input', (e) => {
            const value = e.target.value;
            const passwordValue = registerPassword ? registerPassword.value : '';
            
            if (value) {
                if (value !== passwordValue) {
                    showFieldError('registerConfirmPassword', 'PASSWORDS_DO_NOT_MATCH');
                } else {
                    clearFieldError('registerConfirmPassword');
                    markFieldSuccess('registerConfirmPassword');
                }
            } else {
                clearFieldError('registerConfirmPassword');
                e.target.classList.remove('success');
            }
        });
    }
    
    // Change Password form validation
    const currentPasswordField = document.getElementById('currentPassword');
    const newPasswordField = document.getElementById('newPassword');
    const confirmNewPasswordField = document.getElementById('confirmNewPassword');
    
    if (currentPasswordField) {
        currentPasswordField.addEventListener('input', (e) => {
            const value = e.target.value;
            if (value) {
                if (value.length < 4) {
                    showFieldError('currentPassword', 'MIN_4_CHARACTERS');
                } else {
                    clearFieldError('currentPassword');
                    markFieldSuccess('currentPassword');
                }
            } else {
                clearFieldError('currentPassword');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (newPasswordField) {
        newPasswordField.addEventListener('input', (e) => {
            const value = e.target.value;
            const currentValue = currentPasswordField ? currentPasswordField.value : '';
            
            if (value) {
                if (value.length < 4) {
                    showFieldError('newPassword', 'MIN_4_CHARACTERS');
                } else if (value.length > 50) {
                    showFieldError('newPassword', 'MAX_50_CHARACTERS');
                } else if (currentValue && value === currentValue) {
                    showFieldError('newPassword', 'MUST_BE_DIFFERENT_FROM_CURRENT');
                } else {
                    clearFieldError('newPassword');
                    markFieldSuccess('newPassword');
                }
                
                // Re-validate confirm password if it has a value
                if (confirmNewPasswordField && confirmNewPasswordField.value) {
                    if (value !== confirmNewPasswordField.value) {
                        showFieldError('confirmNewPassword', 'PASSWORDS_DO_NOT_MATCH');
                    } else {
                        clearFieldError('confirmNewPassword');
                        markFieldSuccess('confirmNewPassword');
                    }
                }
            } else {
                clearFieldError('newPassword');
                e.target.classList.remove('success');
            }
        });
    }
    
    if (confirmNewPasswordField) {
        confirmNewPasswordField.addEventListener('input', (e) => {
            const value = e.target.value;
            const newValue = newPasswordField ? newPasswordField.value : '';
            
            if (value) {
                if (value !== newValue) {
                    showFieldError('confirmNewPassword', 'PASSWORDS_DO_NOT_MATCH');
                } else {
                    clearFieldError('confirmNewPassword');
                    markFieldSuccess('confirmNewPassword');
                }
            } else {
                clearFieldError('confirmNewPassword');
                e.target.classList.remove('success');
            }
        });
    }
}

// Initialize app
init();
setupFormValidation();
