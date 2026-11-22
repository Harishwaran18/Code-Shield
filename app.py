from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState
import subprocess
import sys
import json
import os
import asyncio
from datetime import datetime
from typing import Dict, Set, List, Optional
import uvicorn

from dlp import (
    CodeAuditLogger,
    DataLeakPrevention,
    RateLimiter,
    describe_device,
    risk_class_for_score,
)

app = FastAPI(title="SecureHack AI - AI-Powered Secure Collaborative Coding Platform")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create necessary directories
os.makedirs("temp", exist_ok=True)
os.makedirs("static", exist_ok=True)

# Store active WebSocket connections for real-time collaboration
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.user_sessions: Dict[WebSocket, dict] = {}
        self.session_meta: Dict[WebSocket, dict] = {}

    async def connect(self, websocket: WebSocket, session_id: str, user: dict, client: Optional[dict] = None):
        if websocket.application_state == WebSocketState.CONNECTING:
            await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = set()
        self.active_connections[session_id].add(websocket)
        self.user_sessions[websocket] = {"session_id": session_id, "user": user}
        client = client or {}
        self.session_meta[websocket] = {
            "id": f"sess_{os.urandom(4).hex()}",
            "ip": client.get("ip", "unknown"),
            "device": client.get("device", "Unknown"),
            "joined_at": datetime.now(),
            "verified": False,
        }
        
        # Broadcast user joined
        await self.broadcast(session_id, {
            "type": "user_joined",
            "user": user,
            "timestamp": datetime.now().isoformat()
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.user_sessions:
            session_info = self.user_sessions[websocket]
            session_id = session_info["session_id"]
            user = session_info["user"]
            
            if session_id in self.active_connections:
                self.active_connections[session_id].discard(websocket)
                if not self.active_connections[session_id]:
                    del self.active_connections[session_id]
            
            del self.user_sessions[websocket]
            self.session_meta.pop(websocket, None)
            
            # Broadcast user left
            asyncio.create_task(self.broadcast(session_id, {
                "type": "user_left",
                "user": user,
                "timestamp": datetime.now().isoformat()
            }))

    async def broadcast(self, session_id: str, message: dict):
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except:
                    pass

    def snapshot(self) -> List[dict]:
        now = datetime.now()
        sessions = []
        for websocket, meta in list(self.session_meta.items()):
            info = self.user_sessions.get(websocket, {})
            user = info.get("user") or {}
            minutes, seconds = divmod(int((now - meta["joined_at"]).total_seconds()), 60)
            sessions.append({
                "id": meta["id"],
                "user": user.get("name") or user.get("username") or "Anonymous",
                "ip": meta["ip"],
                "device": meta["device"],
                "duration": f"{minutes}m {seconds}s",
                "verified": meta["verified"],
                "session_id": info.get("session_id", "default"),
            })
        return sessions

    def verify(self, session_id: str) -> bool:
        for meta in self.session_meta.values():
            if meta["id"] == session_id:
                meta["verified"] = True
                return True
        return False

    async def terminate(self, session_id: str) -> bool:
        for websocket, meta in list(self.session_meta.items()):
            if meta["id"] != session_id:
                continue
            try:
                await websocket.close(code=4001)
            except Exception:
                pass
            self.disconnect(websocket)
            return True
        return False

manager = ConnectionManager()

dlp_scanner = DataLeakPrevention()
rate_limiter = RateLimiter()
audit_logger = CodeAuditLogger()

# Helper function to read HTML files
def read_html_file(filename: str) -> str:
    """Read HTML file with proper error handling"""
    try:
        # Try current directory first
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Try static directory
        static_path = os.path.join("static", filename)
        if os.path.exists(static_path):
            with open(static_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Try temp directory
        temp_path = os.path.join("temp", filename)
        if os.path.exists(temp_path):
            with open(temp_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        return None
    except Exception as e:
        print(f"Error reading {filename}: {str(e)}")
        return None

# Routes
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecureHack AI - Home</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                padding: 50px;
                max-width: 600px;
                text-align: center;
                animation: slideUp 0.6s ease-out;
            }
            
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            h1 {
                font-size: 3rem;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 20px;
            }
            
            p {
                color: #4b5563;
                font-size: 1.2rem;
                margin-bottom: 30px;
                line-height: 1.6;
            }
            
            .features {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }
            
            .feature {
                padding: 20px;
                background: #f3f4f6;
                border-radius: 10px;
                transition: transform 0.3s;
            }
            
            .feature:hover {
                transform: translateY(-5px);
            }
            
            .feature-icon {
                font-size: 2rem;
                margin-bottom: 10px;
            }
            
            .feature-title {
                font-weight: 600;
                color: #374151;
                margin-bottom: 5px;
            }
            
            .feature-desc {
                font-size: 0.9rem;
                color: #6b7280;
            }
            
            .buttons {
                display: flex;
                gap: 20px;
                justify-content: center;
            }
            
            .btn {
                padding: 15px 40px;
                border: none;
                border-radius: 10px;
                font-size: 1.1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                text-decoration: none;
                display: inline-block;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            }
            
            .btn-secondary {
                background: white;
                color: #4f46e5;
                border: 2px solid #667eea;
            }
            
            .btn-secondary:hover {
                background: #f5f3ff;
                transform: translateY(-2px);
            }
            
            .status {
                margin-top: 30px;
                padding: 15px;
                background: #d1fae5;
                border-radius: 10px;
                color: #065f46;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }
            
            .status.error {
                background: #fee2e2;
                color: #dc2626;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 SecureHack AI</h1>
            <p>AI-Powered Secure Collaborative Coding Platform for Hackathons</p>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">Real-time Collaboration</div>
                    <div class="feature-desc">Code together with your team</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">🤖</div>
                    <div class="feature-title">AI Vulnerability Scanner</div>
                    <div class="feature-desc">Detect security issues instantly</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">📊</div>
                    <div class="feature-title">ML Anomaly Detection</div>
                    <div class="feature-desc">Monitor suspicious behavior</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">Real-time Alerts</div>
                    <div class="feature-desc">Instant security notifications</div>
                </div>
            </div>
            
            <div class="buttons">
                <a href="/login" class="btn btn-primary">Login</a>
                <a href="/editor" class="btn btn-secondary">Try Editor</a>
                <a href="/dashboard" class="btn btn-secondary">Security Dashboard</a>
            </div>
            
            <div class="status" id="status">
                <span>✅</span>
                <span>Server is running</span>
            </div>
        </div>
        
        <script>
            // Check if editor.html exists
            fetch('/editor')
                .then(response => {
                    if (!response.ok) {
                        const status = document.getElementById('status');
                        status.className = 'status error';
                        status.innerHTML = '<span>⚠️</span><span>Editor page not loaded. Please check server logs.</span>';
                    }
                })
                .catch(() => {
                    const status = document.getElementById('status');
                    status.className = 'status error';
                    status.innerHTML = '<span>❌</span><span>Cannot connect to server</span>';
                });
        </script>
    </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve the login page"""
    content = read_html_file("login.html")
    
    if content:
        return HTMLResponse(content=content)
    
    # Fallback login page if file not found
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureHack AI - Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
            }
            .login-box {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                width: 350px;
            }
            h2 {
                text-align: center;
                color: #333;
                margin-bottom: 30px;
            }
            input {
                width: 100%;
                padding: 12px;
                margin: 8px 0 20px;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
            }
            button:hover {
                opacity: 0.9;
            }
            .demo {
                margin-top: 20px;
                padding: 15px;
                background: #f3f4f6;
                border-radius: 5px;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔐 SecureHack AI</h2>
            <form onsubmit="handleLogin(event)">
                <label>Username</label>
                <input type="text" id="username" value="hackathon_user" required>
                <label>Password</label>
                <input type="password" id="password" value="demo123" required>
                <button type="submit">Login</button>
            </form>
            <div class="demo">
                <strong>🎯 Demo Mode</strong><br>
                Use any username/password to login
            </div>
        </div>
        <script>
            function handleLogin(e) {
                e.preventDefault();
                sessionStorage.setItem('currentUser', JSON.stringify({
                    name: document.getElementById('username').value,
                    initials: document.getElementById('username').value.substring(0,2).toUpperCase()
                }));
                window.location.href = '/editor';
            }
        </script>
    </body>
    </html>
    """)

@app.get("/editor", response_class=HTMLResponse)
async def editor_page():
    """Serve the collaborative editor page"""
    content = read_html_file("editor.html")
    
    if content:
        return HTMLResponse(content=content)
    
    # Enhanced fallback editor if file not found
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecureHack AI - Collaborative Editor</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }

            .navbar {
                background: rgba(255, 255, 255, 0.95);
                padding: 1rem 2rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }

            .logo {
                font-size: 1.5rem;
                font-weight: bold;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }

            .user-info {
                display: flex;
                align-items: center;
                gap: 1rem;
            }

            .avatar {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
            }

            .main-container {
                display: flex;
                height: calc(100vh - 70px);
                padding: 20px;
                gap: 20px;
            }

            .editor-section {
                flex: 2;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }

            .editor-header {
                background: #f3f4f6;
                padding: 1rem;
                border-bottom: 1px solid #e5e7eb;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .file-tab {
                display: flex;
                gap: 0.5rem;
                align-items: center;
            }

            .file-tab span {
                background: white;
                padding: 0.5rem 1rem;
                border-radius: 5px;
                font-size: 0.9rem;
                border: 1px solid #e5e7eb;
            }

            .editor-actions {
                display: flex;
                gap: 0.5rem;
            }

            .btn {
                padding: 0.5rem 1rem;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.3s;
            }

            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }

            .btn-success {
                background: #10b981;
                color: white;
            }

            textarea {
                width: 100%;
                height: 100%;
                padding: 1rem;
                border: none;
                outline: none;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                line-height: 1.5;
                resize: none;
            }

            .sidebar {
                flex: 1;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }

            .scan-section {
                padding: 1.5rem;
                border-bottom: 1px solid #e5e7eb;
            }

            .section-title {
                font-size: 1.1rem;
                font-weight: 600;
                color: #374151;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .scan-button {
                width: 100%;
                padding: 0.75rem;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }

            .scan-button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(16, 185, 129, 0.4);
            }

            .results-section {
                flex: 1;
                padding: 1.5rem;
                overflow-y: auto;
            }

            .vulnerability-card {
                background: #fef2f2;
                border-left: 4px solid #ef4444;
                padding: 1rem;
                margin-bottom: 1rem;
                border-radius: 8px;
            }

            .vulnerability-card.high {
                background: #fff7ed;
                border-left-color: #f97316;
            }

            .vulnerability-card.medium {
                background: #fef9c3;
                border-left-color: #eab308;
            }

            .vulnerability-title {
                font-weight: 600;
                color: #111827;
                margin-bottom: 0.5rem;
            }

            .vulnerability-desc {
                font-size: 0.9rem;
                color: #4b5563;
            }

            .cursor-position {
                padding: 0.5rem 1rem;
                background: #f3f4f6;
                border-top: 1px solid #e5e7eb;
                font-size: 0.85rem;
                color: #6b7280;
            }

            .chat-section {
                padding: 1.5rem;
                border-top: 1px solid #e5e7eb;
                height: 250px;
                display: flex;
                flex-direction: column;
            }

            .chat-messages {
                flex: 1;
                overflow-y: auto;
                margin-bottom: 1rem;
            }

            .chat-message {
                margin-bottom: 0.75rem;
                padding: 0.5rem;
                background: #f3f4f6;
                border-radius: 8px;
            }

            .chat-message .user {
                font-weight: 600;
                color: #4f46e5;
                font-size: 0.85rem;
            }

            .chat-message .text {
                color: #374151;
                font-size: 0.9rem;
            }

            .chat-input {
                display: flex;
                gap: 0.5rem;
            }

            .chat-input input {
                flex: 1;
                padding: 0.5rem;
                border: 1px solid #d1d5db;
                border-radius: 5px;
                outline: none;
            }

            .chat-input button {
                padding: 0.5rem 1rem;
                background: #4f46e5;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
            }

            .security-alert {
                position: fixed;
                top: 20px;
                right: 20px;
                background: #ef4444;
                color: white;
                padding: 1rem;
                border-radius: 8px;
                box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
                display: none;
                animation: slideIn 0.3s ease;
                z-index: 1000;
            }

            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }

            .security-alert.show {
                display: block;
            }
        </style>
    </head>
    <body>
        <div class="security-alert" id="securityAlert">
            <strong>🚨 Security Alert!</strong>
            <p id="alertMessage">Suspicious activity detected</p>
        </div>

        <nav class="navbar">
            <div class="logo">SecureHack AI</div>
            <div class="user-info">
                <div class="avatar" id="userAvatar">JD</div>
            </div>
        </nav>

        <div class="main-container">
            <div class="editor-section">
                <div class="editor-header">
                    <div class="file-tab">
                        <span>📄 main.py</span>
                    </div>
                    <div class="editor-actions">
                        <button class="btn btn-primary" onclick="saveCode()">Save</button>
                        <button class="btn" onclick="shareCode()">Share</button>
                    </div>
                </div>
                <textarea id="codeEditor" placeholder="# Write your Python code here...">
# Welcome to SecureHack AI Collaborative Editor
# Try this vulnerable code to test the scanner:

import os
import subprocess

# Hardcoded password (vulnerability)
database_password = "admin123"

# Command injection risk
user_input = "localhost"
os.system("ping " + user_input)

# Use of eval (dangerous!)
user_data = "__import__('os').system('dir')"
eval(user_data)

# Insecure file permissions
with open("secret.txt", "w") as f:
    f.write("API_KEY=12345")
os.chmod("secret.txt", 0o777)

# SQL injection risk
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # Execute query directly - vulnerable!
    return query

# Click scan to detect these issues!
                </textarea>
                <div class="cursor-position" id="cursorPosition">Ln 1, Col 1</div>
            </div>

            <div class="sidebar">
                <div class="scan-section">
                    <div class="section-title">
                        <span>🔍</span>
                        <span>AI Vulnerability Scanner</span>
                    </div>
                    <button class="scan-button" onclick="scanVulnerabilities()" id="scanButton">
                        Scan Code for Vulnerabilities
                    </button>
                </div>

                <div class="results-section" id="results">
                    <div class="section-title">
                        <span>📊</span>
                        <span>Scan Results</span>
                    </div>
                    <div id="scanResults">
                        <div style="text-align: center; color: #9ca3af; padding: 2rem;">
                            Click "Scan Code" to analyze for security vulnerabilities
                        </div>
                    </div>
                </div>

                <div class="chat-section">
                    <div class="section-title">
                        <span>💬</span>
                        <span>Team Chat</span>
                    </div>
                    <div class="chat-messages" id="chatMessages">
                        <div class="chat-message">
                            <span class="user">System:</span>
                            <span class="text">Welcome to the collaborative session!</span>
                            <span class="time">now</span>
                        </div>
                    </div>
                    <div class="chat-input">
                        <input type="text" id="chatInput" placeholder="Type a message..." onkeypress="if(event.key==='Enter') sendMessage()">
                        <button onclick="sendMessage()">Send</button>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const editor = document.getElementById('codeEditor');
            let currentUser = {
                name: 'Hackathon User',
                initials: 'HU'
            };

            // Track cursor position
            editor.addEventListener('click', updateCursorPosition);
            editor.addEventListener('keyup', updateCursorPosition);
            editor.addEventListener('keydown', updateCursorPosition);

            function updateCursorPosition() {
                const pos = editor.selectionStart;
                const text = editor.value.substring(0, pos);
                const lines = text.split('\\n');
                const lineNumber = lines.length;
                const colNumber = lines[lines.length - 1].length + 1;
                document.getElementById('cursorPosition').textContent = `Ln ${lineNumber}, Col ${colNumber}`;
            }

            // Vulnerability scanning
            async function scanVulnerabilities() {
                const button = document.getElementById('scanButton');
                const originalText = button.textContent;
                
                button.textContent = '🔬 Scanning...';
                button.disabled = true;

                const code = editor.value;

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ code: code })
                    });

                    const data = await response.json();
                    displayResults(data);
                    
                    if (data.severity === 'high' || data.severity === 'critical') {
                        triggerAlert('Critical vulnerabilities detected! Check scan results.');
                    }
                } catch (error) {
                    console.error('Scan failed:', error);
                    // Demo mode - show mock results
                    displayMockResults();
                } finally {
                    button.textContent = originalText;
                    button.disabled = false;
                }
            }

            function displayResults(data) {
                const resultsDiv = document.getElementById('scanResults');
                
                if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                    let html = '';
                    data.vulnerabilities.forEach(v => {
                        const severityClass = v.severity || 'medium';
                        html += `
                            <div class="vulnerability-card ${severityClass}">
                                <div class="vulnerability-title">${v.title || 'Security Issue'}</div>
                                <div class="vulnerability-desc">${v.description || 'Potential security vulnerability detected'}</div>
                                <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">
                                    Line ${v.line || 'unknown'} | Severity: ${(v.severity || 'medium').toUpperCase()}
                                </div>
                            </div>
                        `;
                    });
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = `
                        <div style="background:#d1fae5; padding:1rem; border-radius:8px; color:#065f46;">
                            <strong>✅ No vulnerabilities found!</strong>
                            <p style="margin-top:0.5rem; font-size:0.9rem;">Your code looks secure.</p>
                        </div>
                    `;
                }
            }

            function displayMockResults() {
                const resultsDiv = document.getElementById('scanResults');
                resultsDiv.innerHTML = `
                    <div class="vulnerability-card">
                        <div class="vulnerability-title">Hardcoded Password</div>
                        <div class="vulnerability-desc">Hardcoded password 'admin123' detected. Use environment variables instead.</div>
                        <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">Line 7 | Severity: MEDIUM</div>
                    </div>
                    <div class="vulnerability-card high">
                        <div class="vulnerability-title">Command Injection</div>
                        <div class="vulnerability-desc">Use of os.system() with user input. Possible command injection.</div>
                        <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">Line 11 | Severity: HIGH</div>
                    </div>
                    <div class="vulnerability-card high">
                        <div class="vulnerability-title">Arbitrary Code Execution</div>
                        <div class="vulnerability-desc">Use of eval() with user input. Extremely dangerous!</div>
                        <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">Line 15 | Severity: CRITICAL</div>
                    </div>
                    <div class="vulnerability-card medium">
                        <div class="vulnerability-title">Insecure File Permissions</div>
                        <div class="vulnerability-desc">Setting world-writable permissions (0o777) on secret file.</div>
                        <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">Line 20 | Severity: MEDIUM</div>
                    </div>
                    <div class="vulnerability-card high">
                        <div class="vulnerability-title">SQL Injection</div>
                        <div class="vulnerability-desc">SQL query built with string concatenation. Use parameterized queries.</div>
                        <div style="font-size:0.8rem; color:#6b7280; margin-top:0.5rem;">Line 25 | Severity: HIGH</div>
                    </div>
                `;
            }

            function triggerAlert(message) {
                const alert = document.getElementById('securityAlert');
                document.getElementById('alertMessage').textContent = message;
                alert.classList.add('show');
                
                // Play notification sound (optional)
                try {
                    const audio = new Audio('data:audio/wav;base64,UklGRlwAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YVoAAACAgICAf39/f39/f3+AgICAf39/f39/f3+AgICAf39/f39/f3+AgICAf39/f39/f3+AgICAf39/f39/f3+AgICAf39/f38=');
                    audio.play().catch(e => console.log('Audio play failed:', e));
                } catch(e) {}
                
                setTimeout(() => {
                    alert.classList.remove('show');
                }, 5000);
            }

            function saveCode() {
                alert('💾 Code saved to local storage!');
                localStorage.setItem('savedCode', editor.value);
            }

            function shareCode() {
                // Generate shareable link (demo)
                const dummyLink = 'https://securehack.ai/share/' + Math.random().toString(36).substring(7);
                alert('🔗 Share link copied to clipboard!\n' + dummyLink);
                
                // Copy to clipboard
                navigator.clipboard.writeText(dummyLink).catch(e => console.log('Copy failed:', e));
            }

            function sendMessage() {
                const input = document.getElementById('chatInput');
                const message = input.value.trim();
                
                if (message) {
                    const messages = document.getElementById('chatMessages');
                    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    
                    messages.innerHTML += `
                        <div class="chat-message">
                            <span class="user">${currentUser.name}:</span>
                            <span class="text">${message}</span>
                            <span class="time">${time}</span>
                        </div>
                    `;
                    
                    input.value = '';
                    messages.scrollTop = messages.scrollHeight;
                }
            }

            // Load user info
            window.addEventListener('load', () => {
                const savedUser = sessionStorage.getItem('currentUser');
                if (savedUser) {
                    try {
                        currentUser = JSON.parse(savedUser);
                        document.getElementById('userAvatar').textContent = currentUser.initials || 'HU';
                    } catch(e) {}
                }
                
                // Load saved code
                const savedCode = localStorage.getItem('savedCode');
                if (savedCode) {
                    editor.value = savedCode;
                }
            });

            // Auto-save every 30 seconds
            setInterval(() => {
                localStorage.setItem('savedCode', editor.value);
            }, 30000);
        </script>
    </body>
    </html>
    """)

@app.post("/api/login")
async def login(credentials: dict):
    username = credentials.get("username")
    password = credentials.get("password")
    
    # For hackathon, accept any non-empty credentials
    if username:
        return {
            "success": True,
            "user": {
                "username": username,
                "name": username.split('@')[0].replace('.', ' ').title(),
                "initials": username[:2].upper() if len(username) >= 2 else username[0].upper() * 2,
                "session_id": f"sess_{os.urandom(8).hex()}"
            }
        }
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/scan")
async def scan_code(data: dict):
    code = data.get("code", "")

    if not code:
        return {"result": "No code to scan", "severity": "none", "vulnerabilities": []}

    result = run_bandit_scan(code)
    secrets = dlp_scanner.scan_for_secrets(code)

    if secrets:
        result["vulnerabilities"].extend(secrets)
        result["severity"] = highest_severity(v["severity"] for v in result["vulnerabilities"])
        result["result"] = f"Found {len(result['vulnerabilities'])} potential security issues"

    for finding in result["vulnerabilities"]:
        for key, value in finding.items():
            if isinstance(value, str):
                finding[key] = dlp_scanner.redact(value)

    result["secrets_found"] = len(secrets)
    audit_logger.log_scan(data.get("user"), code, result["vulnerabilities"])
    return result

def run_bandit_scan(code: str) -> dict:
    """Run Bandit on the submitted code, falling back to pattern matching."""
    temp_file = os.path.join("temp", f"temp_code_{os.urandom(4).hex()}.py")

    try:
        with open(temp_file, "w", encoding='utf-8') as f:
            f.write(code)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json", temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

        if not result.stdout:
            return {"result": "✅ No security issues detected!", "severity": "none", "vulnerabilities": []}

        try:
            return format_scan_results(json.loads(result.stdout))
        except json.JSONDecodeError:
            return {"result": "Scan completed but results unreadable", "severity": "unknown", "vulnerabilities": []}

    except FileNotFoundError:
        return get_mock_scan_results(code)
    except subprocess.TimeoutExpired:
        return {"result": "Scan timeout", "severity": "error", "vulnerabilities": []}
    except Exception as e:
        print(f"Scan error: {str(e)}")
        return get_mock_scan_results(code)

def highest_severity(severities) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(severities, key=lambda s: order.get(s, 0), default="none")

def get_mock_scan_results(code: str):
    """Return mock scan results for demo when bandit is not available"""
    vulnerabilities = []
    
    # Simple pattern matching for demo
    if "password" in code and "=" in code:
        vulnerabilities.append({
            "title": "Hardcoded Password",
            "description": "Hardcoded password detected. Use environment variables or secure secrets management.",
            "severity": "medium",
            "line": find_line_number(code, "password")
        })
    
    if "os.system" in code:
        vulnerabilities.append({
            "title": "Command Injection Risk",
            "description": "Use of os.system() can lead to command injection. Use subprocess.run() with proper sanitization.",
            "severity": "high",
            "line": find_line_number(code, "os.system")
        })
    
    if "eval(" in code:
        vulnerabilities.append({
            "title": "Arbitrary Code Execution",
            "description": "Use of eval() with user input is extremely dangerous and can lead to code injection.",
            "severity": "critical",
            "line": find_line_number(code, "eval(")
        })
    
    if "subprocess" in code and ("shell=True" in code or "input" in code):
        vulnerabilities.append({
            "title": "Subprocess Security Issue",
            "description": "Using subprocess with shell=True or user input can lead to command injection.",
            "severity": "high",
            "line": find_line_number(code, "subprocess")
        })
    
    if "chmod" in code and "0o777" in code:
        vulnerabilities.append({
            "title": "Insecure File Permissions",
            "description": "Setting world-writable permissions (0o777) on files is a security risk.",
            "severity": "medium",
            "line": find_line_number(code, "chmod")
        })
    
    if "SELECT" in code and "{" in code and "format" in code:
        vulnerabilities.append({
            "title": "SQL Injection Risk",
            "description": "SQL query built with string formatting. Use parameterized queries instead.",
            "severity": "high",
            "line": find_line_number(code, "SELECT")
        })
    
    if vulnerabilities:
        return {
            "result": f"Found {len(vulnerabilities)} potential security issues",
            "severity": max([v["severity"] for v in vulnerabilities], 
                          key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0)),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "result": "✅ No security issues detected!",
            "severity": "none",
            "vulnerabilities": []
        }

def find_line_number(code: str, pattern: str) -> int:
    """Find line number of first occurrence of pattern"""
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        if pattern in line:
            return i
    return 1

def format_scan_results(scan_data):
    """Format Bandit JSON output for display"""
    results = scan_data.get("results", [])
    
    if not results:
        return {
            "result": "✅ No security issues detected!",
            "severity": "none",
            "vulnerabilities": []
        }
    
    formatted = []
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    
    for issue in results:
        formatted.append({
            "filename": issue.get("filename", "unknown"),
            "line": issue.get("line_number", 0),
            "severity": severity_map.get(issue.get("issue_severity", "MEDIUM"), "medium"),
            "confidence": issue.get("issue_confidence", "MEDIUM"),
            "title": issue.get("test_name", "Unknown Issue"),
            "description": issue.get("issue_text", ""),
            "code": issue.get("code", ""),
            "more_info": issue.get("more_info", "")
        })
    
    # Determine overall severity
    severity_order = {"high": 3, "medium": 2, "low": 1}
    max_severity = "none"
    for v in formatted:
        if severity_order.get(v["severity"], 0) > severity_order.get(max_severity, 0):
            max_severity = v["severity"]
    
    return {
        "result": f"Found {len(results)} potential security issues",
        "severity": max_severity,
        "vulnerabilities": formatted
    }

# WebSocket for real-time collaboration
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    # Wait for initial connection message
    try:
        data = await websocket.receive_json()
        session_id = data.get("session_id", "default")
        user = data.get("user", {"name": "Anonymous", "initials": "AN"})
        
        client = {
            "ip": websocket.client.host if websocket.client else "unknown",
            "device": describe_device(websocket.headers.get("user-agent", "")),
        }
        await manager.connect(websocket, session_id, user, client)
        
        # Send current collaborators list
        if session_id in manager.active_connections:
            collaborators = []
            for conn in manager.active_connections[session_id]:
                if conn in manager.user_sessions:
                    collaborators.append(manager.user_sessions[conn]["user"])
            await websocket.send_json({
                "type": "collaborators",
                "users": collaborators
            })
        
        # Handle messages
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")
            
            if message_type == "edit":
                # Broadcast code changes to all users in session
                await manager.broadcast(session_id, {
                    "type": "edit",
                    "user": user,
                    "changes": data.get("changes"),
                    "code": data.get("code"),
                    "timestamp": datetime.now().isoformat()
                })
                
            elif message_type == "cursor":
                # Broadcast cursor position
                await manager.broadcast(session_id, {
                    "type": "cursor",
                    "user": user,
                    "position": data.get("position"),
                    "timestamp": datetime.now().isoformat()
                })
                
            elif message_type == "message":
                # Broadcast chat message
                await manager.broadcast(session_id, {
                    "type": "message",
                    "user": user,
                    "message": data.get("message"),
                    "timestamp": datetime.now().isoformat()
                })
                
            elif message_type == "typing":
                # Broadcast typing indicator
                await manager.broadcast(session_id, {
                    "type": "typing",
                    "user": user,
                    "timestamp": datetime.now().isoformat()
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Security dashboard
ALERT_ICONS = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}

def session_risk_score(session: dict) -> int:
    score = 5
    for event in audit_logger.recent(50):
        if event["user"] != session["user"]:
            continue
        score += {"critical": 40, "high": 20, "medium": 10}.get(event["highest_severity"], 0)
    if session["verified"]:
        score -= 15
    return max(0, min(100, score))

def build_alerts(limit: int = 10) -> List[dict]:
    alerts = []
    for event in audit_logger.recent(limit):
        if event["findings"] <= 0:
            continue
        severity = event["highest_severity"] if event["highest_severity"] in ALERT_ICONS else "low"
        alerts.append({
            "severity": severity,
            "icon": ALERT_ICONS[severity],
            "title": f"{event['findings']} finding(s) in recent scan",
            "message": f"User {event['user']} scanned code {event['code_hash']}",
            "time": event["timestamp"],
        })
    if not alerts:
        alerts.append({
            "severity": "low",
            "icon": "✅",
            "title": "No active alerts",
            "message": "All monitored sessions look healthy.",
            "time": datetime.now().isoformat(),
        })
    return alerts

def build_dashboard_payload() -> dict:
    sessions = manager.snapshot()
    for session in sessions:
        session["risk_score"] = session_risk_score(session)
        session["risk_class"] = risk_class_for_score(session["risk_score"])

    scores = [session["risk_score"] for session in sessions]
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for session in sessions:
        counts[session["risk_class"]] += 1

    return {
        "stats": {
            "active_sessions": len(sessions),
            "anomalies": audit_logger.stats()["anomalies"],
            "avg_risk": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "verified_sessions": sum(1 for session in sessions if session["verified"]),
            "low_risk": counts["low"],
            "medium_risk": counts["medium"],
            "high_risk": counts["high"],
            "critical": counts["critical"],
        },
        "sessions": sessions,
        "alerts": build_alerts(),
        "timestamp": datetime.now().isoformat(),
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    content = read_html_file("dashboard.html")
    if content:
        return HTMLResponse(content=content)
    raise HTTPException(status_code=404, detail="dashboard.html not found")

@app.get("/api/dashboard")
async def dashboard_data():
    return build_dashboard_payload()

@app.get("/api/sessions")
async def list_sessions():
    return {"sessions": build_dashboard_payload()["sessions"]}

@app.post("/api/sessions/{session_id}/verify")
async def verify_session(session_id: str):
    if not manager.verify(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "verified", "session_id": session_id}

@app.post("/api/sessions/{session_id}/terminate")
async def terminate_session(session_id: str):
    if not await manager.terminate(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "terminated", "session_id": session_id}

@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(build_dashboard_payload())
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass

@app.get("/investigate/{session_id}", response_class=HTMLResponse)
async def investigate_session(session_id: str):
    session = next((item for item in manager.snapshot() if item["id"] == session_id), None)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    risk_score = session_risk_score(session)
    rows = "".join(
        f"<tr><th>{key}</th><td>{value}</td></tr>"
        for key, value in {
            "Session ID": session["id"],
            "Collaboration room": session["session_id"],
            "User": session["user"],
            "IP address": session["ip"],
            "Device": session["device"],
            "Connected for": session["duration"],
            "Verified": "Yes" if session["verified"] else "No",
            "Risk score": f"{risk_score} ({risk_class_for_score(risk_score)})",
        }.items()
    )
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Investigate {session_id}</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
table{{border-collapse:collapse;width:100%;max-width:640px}}th,td{{padding:.6rem 1rem;text-align:left;border-bottom:1px solid #334155}}
th{{color:#94a3b8;font-weight:600}}</style></head>
<body><h1>Session investigation</h1><table>{rows}</table></body></html>""")

# Debug endpoint to check file status
@app.get("/debug")
async def debug():
    current_dir = os.getcwd()
    files = os.listdir(current_dir)
    html_files = [f for f in files if f.endswith('.html')]
    
    return {
        "status": "running",
        "current_directory": current_dir,
        "html_files": html_files,
        "editor_exists": "editor.html" in html_files,
        "login_exists": "login.html" in html_files,
        "full_paths": {
            "editor": os.path.join(current_dir, "editor.html") if "editor.html" in html_files else None,
            "login": os.path.join(current_dir, "login.html") if "login.html" in html_files else None
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "bandit_installed": check_bandit_installed()
    }

def check_bandit_installed():
    """Check if bandit is installed"""
    try:
        result = subprocess.run([sys.executable, "-m", "bandit", "--version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

# Create necessary files if they don't exist
def create_missing_files():
    """Create editor.html if it doesn't exist"""
    if not os.path.exists("editor.html"):
        print("📝 Creating editor.html...")
        # The fallback editor is already in the route, so we don't need to create a file
        pass

# Run this when starting
create_missing_files()

if __name__ == "__main__":
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "8000"))
    print("\n" + "="*60)
    print("🚀 SecureHack AI Server")
    print("="*60)
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"📄 Python version: {sys.version.split()[0]}")
    print(f"🔍 Bandit installed: {check_bandit_installed()}")
    print("\n📊 Available endpoints:")
    print(f"   ✓ http://{HOST}:{PORT}/ - Home page")
    print(f"   ✓ http://{HOST}:{PORT}/login - Login page")
    print(f"   ✓ http://{HOST}:{PORT}/editor - Collaborative editor")
    print(f"   ✓ http://{HOST}:{PORT}/dashboard - Security dashboard")
    print(f"   ✓ http://{HOST}:{PORT}/health - Health check")
    print(f"   ✓ http://{HOST}:{PORT}/debug - Debug info")
    print(f"   ✓ ws://{HOST}:{PORT}/ws - WebSocket for collaboration")
    print("\n" + "="*60)
    print(f"🌐 Server starting at: http://{HOST}:{PORT}")
    print("🔍 Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    uvicorn.run(
        "app:app",
        host=HOST,
        port=PORT,
        reload=os.getenv("RELOAD", "1") == "1"
    )