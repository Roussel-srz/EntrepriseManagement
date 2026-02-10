const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../')));

// Database initialization
const db = new sqlite3.Database('./enterprise.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        permissions TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1
    )`);

    // User sessions table
    db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Audit logs table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        table_name TEXT,
        record_id INTEGER,
        old_values TEXT,
        new_values TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS produits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        description TEXT,
        prix_unitaire REAL DEFAULT 0,
        quantite_stock INTEGER DEFAULT 0,
        seuil_alerte INTEGER DEFAULT 10,
        categorie TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Sales table
    db.run(`CREATE TABLE IF NOT EXISTS ventes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        produit_id INTEGER,
        quantite INTEGER NOT NULL,
        prix_unitaire REAL NOT NULL,
        montant_total REAL NOT NULL,
        client_nom TEXT,
        client_telephone TEXT,
        date_ajout DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (produit_id) REFERENCES produits (id)
    )`);

    // Credits table
    db.run(`CREATE TABLE IF NOT EXISTS credits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_nom TEXT NOT NULL,
        client_telephone TEXT,
        montant_total REAL NOT NULL,
        montant_paye REAL DEFAULT 0,
        montant_restant REAL NOT NULL,
        date_echeance DATE,
        statut TEXT DEFAULT 'en_attente',
        date_ajout DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Expenses table
    db.run(`CREATE TABLE IF NOT EXISTS depenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT NOT NULL,
        montant REAL NOT NULL,
        categorie TEXT,
        date_ajout DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create default admin user
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role, permissions) 
            VALUES (?, ?, ?, ?, ?)`, 
            ['admin', 'admin@enterprise.com', adminPassword, 'admin', JSON.stringify(['all'])]);
});

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Permission middleware
const checkPermission = (permission) => {
    return (req, res, next) => {
        const userPermissions = req.user.permissions || [];
        if (req.user.role === 'admin' || userPermissions.includes('all') || userPermissions.includes(permission)) {
            next();
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    };
};

// Auth routes
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        db.get('SELECT * FROM users WHERE username = ? AND is_active = 1', [username], async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Update last login
            db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username, 
                    role: user.role, 
                    permissions: JSON.parse(user.permissions || '[]')
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Store session
            db.run('INSERT INTO user_sessions (user_id, token, expires_at) VALUES (?, ?, ?)', 
                [user.id, token, new Date(Date.now() + 24 * 60 * 60 * 1000)]);

            res.json({
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    permissions: JSON.parse(user.permissions || '[]')
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
    db.run('UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const { current_password, new_password } = req.body;
    
    try {
        // Get user from database
        db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Verify current password
            const validPassword = await bcrypt.compare(current_password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }

            // Hash new password
            const hashedPassword = await bcrypt.hash(new_password, 10);

            // Update password
            db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update password' });
                }

                // Log audit
                logAudit(req.user.id, 'CHANGE_PASSWORD', 'users', req.user.id, null, JSON.stringify({ timestamp: new Date().toISOString() }));

                res.json({ message: 'Password changed successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User management routes (admin only)
app.get('/api/users', authenticateToken, checkPermission('user_management'), (req, res) => {
    db.all('SELECT id, username, email, role, permissions, created_at, last_login, is_active FROM users', (err, users) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        const formattedUsers = users.map(user => ({
            ...user,
            permissions: JSON.parse(user.permissions || '[]')
        }));
        
        res.json(formattedUsers);
    });
});

app.post('/api/users', authenticateToken, checkPermission('user_management'), async (req, res) => {
    const { username, email, password, role, permissions } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (username, email, password, role, permissions) VALUES (?, ?, ?, ?, ?)', 
            [username, email, hashedPassword, role, JSON.stringify(permissions || [])], 
            function(err) {
                if (err) return res.status(500).json({ error: 'User creation failed' });
                
                // Log audit
                logAudit(req.user.id, 'CREATE_USER', 'users', this.lastID, null, JSON.stringify({ username, email, role }));
                
                res.json({ message: 'User created successfully', userId: this.lastID });
            });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/users/:id', authenticateToken, checkPermission('user_management'), async (req, res) => {
    const { id } = req.params;
    const { username, email, role, permissions, is_active, password } = req.body;

    db.get('SELECT * FROM users WHERE id = ?', [id], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });

        const oldValues = JSON.stringify(user);
        
        let updateQuery = 'UPDATE users SET username = ?, email = ?, role = ?, permissions = ?, is_active = ?';
        let updateParams = [username, email, role, JSON.stringify(permissions || []), is_active];
        
        // Add password to update if provided
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', password = ?';
            updateParams.push(hashedPassword);
        }
        
        updateQuery += ' WHERE id = ?';
        updateParams.push(id);
        
        db.run(updateQuery, updateParams, function(err) {
            if (err) return res.status(500).json({ error: 'User update failed' });
            
            // Log audit
            logAudit(req.user.id, 'UPDATE_USER', 'users', id, oldValues, JSON.stringify({ username, email, role, permissions, is_active }));
            
            res.json({ message: 'User updated successfully' });
        });
    });
});

app.delete('/api/users/:id', authenticateToken, checkPermission('user_management'), (req, res) => {
    const { id } = req.params;
    
    // Prevent self-deletion
    if (parseInt(id) === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        
        const oldValues = JSON.stringify(user);
        
        db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
            if (err) return res.status(500).json({ error: 'User deletion failed' });
            
            // Log audit
            logAudit(req.user.id, 'DELETE_USER', 'users', id, oldValues, null);
            
            res.json({ message: 'User deleted successfully' });
        });
    });
});

// Audit logs endpoint
app.get('/api/audit-logs', authenticateToken, checkPermission('user_management'), (req, res) => {
    const { page = 1, limit = 50, user_id, action, table_name } = req.query;
    const offset = (page - 1) * limit;
    
    let whereClause = 'WHERE 1=1';
    let params = [];
    
    if (user_id) {
        whereClause += ' AND al.user_id = ?';
        params.push(user_id);
    }
    
    if (action) {
        whereClause += ' AND al.action LIKE ?';
        params.push(`%${action}%`);
    }
    
    if (table_name) {
        whereClause += ' AND al.table_name LIKE ?';
        params.push(`%${table_name}%`);
    }
    
    const query = `
        SELECT al.*, u.username 
        FROM audit_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        ${whereClause} 
        ORDER BY al.timestamp DESC 
        LIMIT ? OFFSET ?
    `;
    
    params.push(parseInt(limit), offset);
    
    db.all(query, params, (err, logs) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        // Get total count for pagination
        const countQuery = `SELECT COUNT(*) as total FROM audit_logs al ${whereClause}`;
        db.get(countQuery, params.slice(0, -2), (err, countResult) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            res.json({
                logs: logs.map(log => ({
                    ...log,
                    old_values: log.old_values ? JSON.parse(log.old_values) : null,
                    new_values: log.new_values ? JSON.parse(log.new_values) : null
                })),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: countResult.total,
                    pages: Math.ceil(countResult.total / limit)
                }
            });
        });
    });
});

// Data export endpoint
app.get('/api/export/:table', authenticateToken, (req, res) => {
    const { table } = req.params;
    const { format = 'json', start_date, end_date } = req.query;
    
    console.log(`Export request: table=${table}, format=${format}, start_date=${start_date}, end_date=${end_date}`);
    
    // Validate table name
    const allowedTables = ['users', 'ventes', 'produits', 'credits', 'depenses', 'audit_logs'];
    if (!allowedTables.includes(table)) {
        console.log(`Invalid table name: ${table}`);
        return res.status(400).json({ error: 'Invalid table name' });
    }
    
    let query = `SELECT * FROM ${table}`;
    let params = [];
    
    // Add date filtering if provided
    if (start_date && end_date) {
        // Check if created_at column exists, fallback to date_ajout for ventes table
        if (table === 'ventes') {
            query += ' WHERE date_ajout BETWEEN ? AND ?';
        } else {
            query += ' WHERE created_at BETWEEN ? AND ?';
        }
        params.push(start_date, end_date);
    }
    
    // Add appropriate ORDER BY clause
    if (table === 'ventes') {
        query += ' ORDER BY date_ajout DESC';
    } else {
        query += ' ORDER BY created_at DESC';
    }
    
    console.log(`Executing query: ${query} with params:`, params);
    
    db.all(query, params, (err, data) => {
        if (err) {
            console.error('Database error during export:', err);
            return res.status(500).json({ error: 'Database error', details: err.message });
        }
        
        console.log(`Export successful: ${data.length} records found`);
        
        // Log export action
        logAudit(req.user.id, 'EXPORT', table, null, null, JSON.stringify({ 
            format, 
            record_count: data.length,
            date_range: { start_date, end_date }
        }));
        
        try {
            if (format === 'csv') {
                // Convert to CSV
                const csv = convertToCSV(data);
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', `attachment; filename="${table}_export.csv"`);
                res.send(csv);
            } else {
                // Return JSON
                res.setHeader('Content-Type', 'application/json');
                res.setHeader('Content-Disposition', `attachment; filename="${table}_export.json"`);
                res.json(data);
            }
        } catch (error) {
            console.error('Error during export conversion:', error);
            res.status(500).json({ error: 'Export conversion failed', details: error.message });
        }
    });
});

// Data import endpoint
app.post('/api/import/:table', authenticateToken, checkPermission('user_management'), (req, res) => {
    const { table } = req.params;
    const { data } = req.body;
    
    console.log(`Import request: table=${table}, data length=${data ? data.length : 'undefined'}`);
    
    // Validate table name
    const allowedTables = ['users', 'ventes', 'produits', 'credits', 'depenses'];
    if (!allowedTables.includes(table)) {
        console.log(`Invalid table name: ${table}`);
        return res.status(400).json({ error: 'Invalid table name' });
    }
    
    if (!Array.isArray(data) || data.length === 0) {
        console.log('Invalid data format or empty data');
        return res.status(400).json({ error: 'Invalid data format' });
    }
    
    // Get columns for the table
    db.all(`PRAGMA table_info(${table})`, (err, columns) => {
        if (err) {
            console.error('Error getting table info:', err);
            return res.status(500).json({ error: 'Database error', details: err.message });
        }
        
        const columnNames = columns.map(col => col.name);
        console.log(`Table columns: ${columnNames.join(', ')}`);
        
        // Handle special cases for different tables
        let insertQuery;
        if (table === 'users') {
            // Skip password for users if not provided, hash if provided
            insertQuery = `INSERT INTO users (${columnNames.join(', ')}) VALUES (${columnNames.map(() => '?').join(', ')})`;
        } else {
            insertQuery = `INSERT INTO ${table} (${columnNames.join(', ')}) VALUES (${columnNames.map(() => '?').join(', ')})`;
        }
        
        let successCount = 0;
        let errorCount = 0;
        const errors = [];
        
        data.forEach((row, index) => {
            try {
                const values = columnNames.map(col => {
                    if (col === 'id' && row[col]) {
                        // Skip ID for auto-increment
                        return null;
                    }
                    if (col === 'password' && row[col]) {
                        // Hash password for users table
                        return bcrypt.hashSync(row[col], 10);
                    }
                    return row[col] || null;
                });
                
                // Filter out null ID values for auto-increment columns
                const filteredColumns = columnNames.filter((col, idx) => !(col === 'id' && values[idx] === null));
                const filteredValues = values.filter((val, idx) => !(columnNames[idx] === 'id' && val === null));
                
                const finalInsertQuery = `INSERT INTO ${table} (${filteredColumns.join(', ')}) VALUES (${filteredValues.map(() => '?').join(', ')})`;
                
                db.run(finalInsertQuery, filteredValues, function(err) {
                    if (err) {
                        console.error(`Error importing row ${index + 1}:`, err);
                        errorCount++;
                        errors.push({ row: index + 1, error: err.message });
                    } else {
                        successCount++;
                    }
                    
                    // Check if all rows are processed
                    if (successCount + errorCount === data.length) {
                        console.log(`Import completed: ${successCount} success, ${errorCount} errors`);
                        
                        // Log import action
                        logAudit(req.user.id, 'IMPORT', table, null, null, JSON.stringify({ 
                            total_records: data.length,
                            success_count: successCount,
                            error_count: errorCount,
                            errors: errors.slice(0, 10) // Limit error details
                        }));
                        
                        res.json({
                            message: 'Import completed',
                            total_records: data.length,
                            success_count: successCount,
                            error_count: errorCount,
                            errors: errors
                        });
                    }
                });
            } catch (error) {
                console.error(`Error processing row ${index + 1}:`, error);
                errorCount++;
                errors.push({ row: index + 1, error: error.message });
                
                if (successCount + errorCount === data.length) {
                    console.log(`Import completed: ${successCount} success, ${errorCount} errors`);
                    
                    logAudit(req.user.id, 'IMPORT', table, null, null, JSON.stringify({ 
                        total_records: data.length,
                        success_count: successCount,
                        error_count: errorCount,
                        errors: errors.slice(0, 10)
                    }));
                    
                    res.json({
                        message: 'Import completed',
                        total_records: data.length,
                        success_count: successCount,
                        error_count: errorCount,
                        errors: errors
                    });
                }
            }
        });
    });
});

// Helper function to convert JSON to CSV
function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvHeaders = headers.join(',');
    
    const csvRows = data.map(row => {
        return headers.map(header => {
            const value = row[header];
            // Handle null/undefined values
            if (value === null || value === undefined) return '';
            // Handle values with commas or quotes
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                return `"${value.replace(/"/g, '""')}"`;
            }
            return value;
        }).join(',');
    });
    
    return [csvHeaders, ...csvRows].join('\n');
}

// Audit logging function
function logAudit(userId, action, tableName, recordId, oldValues, newValues) {
    db.run('INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values) VALUES (?, ?, ?, ?, ?, ?)', 
        [userId, action, tableName, recordId, oldValues, newValues]);
}

// Real-time collaboration with Socket.IO
const activeUsers = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('join', (userData) => {
        activeUsers.set(socket.id, userData);
        socket.broadcast.emit('user_joined', userData);
        io.emit('active_users', Array.from(activeUsers.values()));
    });

    socket.on('data_change', (data) => {
        socket.broadcast.emit('data_updated', data);
        
        // Log audit if user is authenticated
        if (data.userId) {
            logAudit(data.userId, data.action, data.table, data.recordId, data.oldValues, data.newValues);
        }
    });

    socket.on('disconnect', () => {
        const userData = activeUsers.get(socket.id);
        activeUsers.delete(socket.id);
        socket.broadcast.emit('user_left', userData);
        io.emit('active_users', Array.from(activeUsers.values()));
        console.log('User disconnected:', socket.id);
    });
});

// Serve the main application
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../index.html'));
});

server.listen(PORT, () => {
    console.log(`Multi-user Enterprise Management Server running on port ${PORT}`);
});
