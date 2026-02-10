// Authentication and authorization module for frontend
class AuthManager {
    constructor() {
        this.token = localStorage.getItem('authToken');
        this.user = JSON.parse(localStorage.getItem('currentUser') || 'null');
        this.socket = null;
    }

    // Login method
    async login(username, password) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                throw new Error('Identifiants invalides');
            }

            const data = await response.json();
            this.token = data.token;
            this.user = data.user;
            
            localStorage.setItem('authToken', this.token);
            localStorage.setItem('currentUser', JSON.stringify(this.user));
            
            // Initialize socket connection
            this.initSocket();
            
            return { success: true, user: this.user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Logout method
    async logout() {
        try {
            if (this.token) {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearAuth();
            window.location.href = '/login.html';
        }
    }

    // Clear authentication data
    clearAuth() {
        this.token = null;
        this.user = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.token && !!this.user;
    }

    // Check user permissions
    hasPermission(permission) {
        if (!this.user) return false;
        if (this.user.role === 'admin') return true;
        const permissions = this.user.permissions || [];
        return permissions.includes('all') || permissions.includes(permission);
    }

    // Get authorization header
    getAuthHeader() {
        return this.token ? { 'Authorization': `Bearer ${this.token}` } : {};
    }

    // Initialize socket connection
    initSocket() {
        if (this.socket) {
            this.socket.disconnect();
        }

        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.socket.emit('join', {
                userId: this.user.id,
                username: this.user.username,
                role: this.user.role
            });
        });

        this.socket.on('data_updated', (data) => {
            this.handleRealtimeUpdate(data);
        });

        this.socket.on('active_users', (users) => {
            this.updateActiveUsers(users);
        });

        this.socket.on('user_joined', (user) => {
            this.showNotification(`${user.username} s'est connecté`, 'info');
        });

        this.socket.on('user_left', (user) => {
            this.showNotification(`${user.username} s'est déconnecté`, 'info');
        });
    }

    // Handle real-time data updates
    handleRealtimeUpdate(data) {
        // Emit custom event for components to listen to
        window.dispatchEvent(new CustomEvent('dataUpdated', { detail: data }));
        
        // Show notification for important changes
        if (data.action === 'CREATE' || data.action === 'DELETE') {
            this.showNotification(`Donnée ${data.action.toLowerCase()}: ${data.table}`, 'warning');
        }
    }

    // Update active users display
    updateActiveUsers(users) {
        const activeUsersElement = document.getElementById('active-users');
        if (activeUsersElement) {
            activeUsersElement.innerHTML = users.map(user => 
                `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                    ${user.username}
                </span>`
            ).join('');
        }
    }

    // Show notification
    showNotification(message, type = 'info') {
        // Use existing toast system if available
        if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    }

    // Emit data changes to other users
    emitDataChange(action, table, recordId, oldValues = null, newValues = null) {
        if (this.socket && this.user) {
            this.socket.emit('data_change', {
                userId: this.user.id,
                action,
                table,
                recordId,
                oldValues,
                newValues,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Refresh current user data
    async refreshUserData() {
        try {
            const response = await fetch('/api/auth/me', {
                headers: this.getAuthHeader()
            });

            if (response.ok) {
                const data = await response.json();
                this.user = data.user;
                localStorage.setItem('currentUser', JSON.stringify(this.user));
                return this.user;
            }
        } catch (error) {
            console.error('Failed to refresh user data:', error);
        }
        return null;
    }
}

// Global auth manager instance
const auth = new AuthManager();

// API wrapper with authentication
class API {
    static async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...auth.getAuthHeader()
            }
        };

        const response = await fetch(url, { ...defaultOptions, ...options });

        if (response.status === 401) {
            auth.clearAuth();
            window.location.href = '/login.html';
            return null;
        }

        if (response.status === 403) {
            showToast('Permissions insuffisantes', 'error');
            return null;
        }

        return response;
    }

    static async get(url) {
        const response = await this.request(url);
        return response ? response.json() : null;
    }

    static async post(url, data) {
        const response = await this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        return response ? response.json() : null;
    }

    static async put(url, data) {
        const response = await this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
        return response ? response.json() : null;
    }

    static async delete(url) {
        const response = await this.request(url, {
            method: 'DELETE'
        });
        return response ? response.json() : null;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AuthManager, API, auth };
}
