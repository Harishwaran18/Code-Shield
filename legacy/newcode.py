"""
===============================================================================
SecureHack AI - Multi-User Mobile Login System with Shareable Credentials
===============================================================================
Features:
- 6 pre-configured user accounts
- Shareable credentials page
- Mobile-responsive UI
- Real-time user tracking
- MongoDB integration
===============================================================================
"""

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os
import secrets
import json
import subprocess
import tempfile
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# ==================== MONGODB IMPORTS ====================
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
import gridfs
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# ==================== FASTAPI IMPORTS ====================
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Header, UploadFile, File, Form, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ==================== CUSTOM JSON ENCODER ====================

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle MongoDB ObjectId and datetime"""
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)

# ==================== COLOR CODES FOR TERMINAL ====================

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ==================== TERMINAL LOGGER ====================

class TerminalLogger:
    """Logs all activities to terminal with colors"""
    
    @staticmethod
    def timestamp():
        return datetime.now().strftime("%H:%M:%S")
    
    @staticmethod
    def user_login(username: str, risk_score: float, risk_level: str, device: str = "Web", ip: str = "127.0.0.1"):
        color = Colors.GREEN if risk_level == 'LOW' else Colors.YELLOW if risk_level == 'MEDIUM' else Colors.RED
        device_icon = "📱" if "Mobile" in device or "Android" in device or "iOS" in device else "💻"
        print(f"\n{Colors.BOLD}{Colors.GREEN}[{TerminalLogger.timestamp()}] {device_icon} USER LOGIN{Colors.END}")
        print(f"   {Colors.CYAN}Username:{Colors.END} {Colors.BOLD}{username}{Colors.END}")
        print(f"   {Colors.CYAN}Risk Score:{Colors.END} {color}{risk_score:.1f}{Colors.END} ({risk_level})")
        print(f"   {Colors.CYAN}Device:{Colors.END} {device}")
        print(f"   {Colors.CYAN}IP Address:{Colors.END} {ip}")
        print(f"   {Colors.CYAN}Time:{Colors.END} {TerminalLogger.timestamp()}")
    
    @staticmethod
    def share_link_accessed(ip: str, device: str):
        print(f"\n{Colors.BOLD}{Colors.CYAN}[{TerminalLogger.timestamp()}] 🔗 SHARE LINK ACCESSED{Colors.END}")
        print(f"   {Colors.CYAN}Device:{Colors.END} {device}")
        print(f"   {Colors.CYAN}IP Address:{Colors.END} {ip}")
        print(f"   {Colors.CYAN}Time:{Colors.END} {TerminalLogger.timestamp()}")
    
    @staticmethod
    def system_stats(active_users: int, active_sessions: int, total_alerts: int, users: List[str]):
        print(f"\n{Colors.BOLD}{Colors.CYAN}[{TerminalLogger.timestamp()}] 📊 SYSTEM STATS{Colors.END}")
        print(f"   {Colors.CYAN}Active Users:{Colors.END} {active_users}")
        print(f"   {Colors.CYAN}Active Sessions:{Colors.END} {active_sessions}")
        print(f"   {Colors.CYAN}Total Alerts:{Colors.END} {total_alerts}")
        print(f"   {Colors.CYAN}Users Online:{Colors.END}")
        for user in users:
            print(f"     • {user}")
        print(f"   {Colors.CYAN}Timestamp:{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

logger = TerminalLogger()

# ==================== MONGODB CONNECTION ====================

class MongoDB:
    """MongoDB connection manager"""
    
    def __init__(self):
        self.connection_string = "mongodb://localhost:27017/"
        self.client = None
        self.db = None
        self.fs = None
        self.is_connected = False
        self.connect()
    
    def connect(self):
        """Establish MongoDB connection"""
        try:
            self.client = MongoClient(self.connection_string, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client['securehack_db']
            self.fs = gridfs.GridFS(self.db)
            
            # Create indexes
            self._create_indexes()
            
            # Initialize default users
            self._init_default_users()
            
            self.is_connected = True
            print(f"{Colors.GREEN}✅ MongoDB Connected Successfully{Colors.END}")
            return True
        except Exception as e:
            self.is_connected = False
            print(f"{Colors.YELLOW}⚠️ MongoDB Connection Failed: {e}{Colors.END}")
            return False
    
    def _create_indexes(self):
        """Create indexes for faster queries"""
        try:
            self.db.users.create_index("username", unique=True)
            self.db.sessions.create_index("session_id", unique=True)
            self.db.sessions.create_index("user_id")
            self.db.sessions.create_index("login_time", DESCENDING)
            self.db.alerts.create_index("timestamp", DESCENDING)
            self.db.alerts.create_index("user_id")
            self.db.scans.create_index("timestamp", DESCENDING)
            self.db.scans.create_index("user_id")
            self.db.behavioral_data.create_index("user_id")
            self.db.behavioral_data.create_index("timestamp", DESCENDING)
            self.db.sessions.create_index("active")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️ Index creation warning: {e}{Colors.END}")
    
    def _init_default_users(self):
        """Initialize default user accounts"""
        default_users = [
            {
                'username': 'admin',
                'password': 'admin123',
                'email': 'admin@securehack.com',
                'full_name': 'Administrator',
                'role': 'admin',
                'department': 'IT',
                'risk_level': 'LOW',
                'risk_score': 10,
                'anomaly_count': 0,
                'avatar': '👑',
                'color': '#ef4444',
                'created_at': datetime.now(),
                'last_login': None
            },
            {
                'username': 'alice',
                'password': 'alice123',
                'email': 'alice@company.com',
                'full_name': 'Alice Johnson',
                'role': 'developer',
                'department': 'Engineering',
                'risk_level': 'LOW',
                'risk_score': 15,
                'anomaly_count': 0,
                'avatar': '👩‍💻',
                'color': '#10b981',
                'created_at': datetime.now(),
                'last_login': None
            },
            {
                'username': 'bob',
                'password': 'bob123',
                'email': 'bob@company.com',
                'full_name': 'Bob Smith',
                'role': 'developer',
                'department': 'Engineering',
                'risk_level': 'LOW',
                'risk_score': 20,
                'anomaly_count': 0,
                'avatar': '👨‍💻',
                'color': '#3b82f6',
                'created_at': datetime.now(),
                'last_login': None
            },
            {
                'username': 'charlie',
                'password': 'charlie123',
                'email': 'charlie@company.com',
                'full_name': 'Charlie Brown',
                'role': 'analyst',
                'department': 'Security',
                'risk_level': 'LOW',
                'risk_score': 12,
                'anomaly_count': 0,
                'avatar': '📊',
                'color': '#f59e0b',
                'created_at': datetime.now(),
                'last_login': None
            },
            {
                'username': 'david',
                'password': 'david123',
                'email': 'david@company.com',
                'full_name': 'David Wilson',
                'role': 'manager',
                'department': 'Management',
                'risk_level': 'LOW',
                'risk_score': 8,
                'anomaly_count': 0,
                'avatar': '💼',
                'color': '#8b5cf6',
                'created_at': datetime.now(),
                'last_login': None
            },
            {
                'username': 'eve',
                'password': 'eve123',
                'email': 'eve@company.com',
                'full_name': 'Eve Adams',
                'role': 'intern',
                'department': 'Engineering',
                'risk_level': 'MEDIUM',
                'risk_score': 35,
                'anomaly_count': 1,
                'avatar': '🎓',
                'color': '#ec4899',
                'created_at': datetime.now(),
                'last_login': None
            }
        ]
        
        for user in default_users:
            try:
                existing = self.db.users.find_one({"username": user['username']})
                if not existing:
                    self.db.users.insert_one(user)
                    print(f"{Colors.GREEN}   ✓ Created user: {user['username']} ({user['password']}){Colors.END}")
            except Exception as e:
                pass
    
    # User operations
    def get_user(self, username: str) -> Optional[dict]:
        if not self.is_connected:
            return None
        try:
            user = self.db.users.find_one({"username": username})
            if user:
                user['_id'] = str(user['_id'])
            return user
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[dict]:
        """Authenticate user with password"""
        if not self.is_connected:
            return None
        try:
            user = self.db.users.find_one({
                "username": username,
                "password": password
            })
            if user:
                user['_id'] = str(user['_id'])
                # Update last login
                self.db.users.update_one(
                    {"username": username},
                    {"$set": {"last_login": datetime.now()}}
                )
            return user
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None
    
    def update_user(self, username: str, update_data: dict) -> bool:
        if not self.is_connected:
            return False
        try:
            result = self.db.users.update_one(
                {"username": username},
                {"$set": update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    def get_all_users(self) -> List[dict]:
        if not self.is_connected:
            return []
        try:
            users = list(self.db.users.find())
            for user in users:
                user['_id'] = str(user['_id'])
            return users
        except Exception as e:
            print(f"Error getting users: {e}")
            return []
    
    # Session operations
    def create_session(self, session_data: dict) -> Optional[str]:
        if not self.is_connected:
            return None
        try:
            # Check if session already exists
            existing = self.db.sessions.find_one({"session_id": session_data['session_id']})
            if existing:
                return str(existing['_id'])
            result = self.db.sessions.insert_one(session_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    def end_session(self, session_id: str):
        if not self.is_connected:
            return
        try:
            self.db.sessions.update_one(
                {"session_id": session_id},
                {"$set": {"active": False, "end_time": datetime.now()}}
            )
        except Exception as e:
            print(f"Error ending session: {e}")
    
    def get_active_sessions(self) -> List[dict]:
        if not self.is_connected:
            return []
        try:
            sessions = list(self.db.sessions.find({"active": True}))
            for s in sessions:
                s['_id'] = str(s['_id'])
            return sessions
        except Exception as e:
            print(f"Error getting active sessions: {e}")
            return []
    
    def get_active_users(self) -> List[str]:
        """Get list of currently active users"""
        if not self.is_connected:
            return []
        try:
            active_sessions = self.db.sessions.find({"active": True})
            users = set()
            for session in active_sessions:
                users.add(session.get('user_id'))
            return list(users)
        except Exception as e:
            print(f"Error getting active users: {e}")
            return []
    
    # Alert operations
    def create_alert(self, alert_data: dict) -> Optional[str]:
        if not self.is_connected:
            return None
        try:
            result = self.db.alerts.insert_one(alert_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
    
    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        if not self.is_connected:
            return []
        try:
            alerts = list(self.db.alerts.find().sort("timestamp", DESCENDING).limit(limit))
            for a in alerts:
                a['_id'] = str(a['_id'])
            return alerts
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    # Analytics
    def get_dashboard_stats(self) -> dict:
        if not self.is_connected:
            return {}
        try:
            total_users = self.db.users.count_documents({})
            active_sessions = self.db.sessions.count_documents({"active": True})
            total_alerts = self.db.alerts.count_documents({})
            active_users = self.get_active_users()
            
            risk_dist = {
                'LOW': self.db.users.count_documents({"risk_level": "LOW"}),
                'MEDIUM': self.db.users.count_documents({"risk_level": "MEDIUM"}),
                'HIGH': self.db.users.count_documents({"risk_level": "HIGH"}),
                'CRITICAL': self.db.users.count_documents({"risk_level": "CRITICAL"})
            }
            
            recent_logins = list(self.db.sessions.find().sort("login_time", -1).limit(5))
            for login in recent_logins:
                login['_id'] = str(login['_id']) if '_id' in login else None
                if 'login_time' in login and isinstance(login['login_time'], datetime):
                    login['login_time'] = login['login_time'].isoformat()
            
            return {
                'total_users': total_users,
                'active_sessions': active_sessions,
                'total_alerts': total_alerts,
                'risk_distribution': risk_dist,
                'recent_logins': recent_logins,
                'active_users': active_users,
                'active_users_count': len(active_users)
            }
        except Exception as e:
            print(f"Error getting dashboard stats: {e}")
            return {}

# ==================== ML MODEL ====================

class SecureHackMLModel:
    """ML model for anomaly detection using ensemble methods"""
    
    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = None
        self.feature_names = [
            'typing_speed_avg', 'typing_speed_std', 'typing_consistency',
            'session_duration', 'keystroke_count', 'error_rate',
            'paste_events', 'copy_events', 'tab_switches',
            'mouse_distance', 'command_frequency', 'focus_losses'
        ]
        self.is_trained = False
        self.model_accuracy = 0.0
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize with pre-trained models using synthetic data"""
        print("🤖 Loading SecureHack ML models...")
        
        np.random.seed(42)
        X_train = []
        y_train = []
        
        # Normal users (1000 samples)
        for _ in range(1000):
            features = [
                float(np.random.normal(200, 30)),
                float(np.random.exponential(15)),
                float(100 - np.random.gamma(2, 5)),
                float(np.random.exponential(30)),
                float(np.random.poisson(500)),
                float(np.random.beta(1, 20) * 100),
                float(np.random.poisson(2)),
                float(np.random.poisson(3)),
                float(np.random.poisson(5)),
                float(np.random.normal(5000, 1000)),
                float(np.random.poisson(10)),
                float(np.random.poisson(2))
            ]
            X_train.append(features)
            y_train.append(0)
        
        # Anomalies (200 samples)
        for _ in range(200):
            features = [
                float(np.random.normal(500, 100)),
                float(np.random.exponential(50)),
                float(np.random.uniform(10, 40)),
                float(np.random.exponential(120)),
                float(np.random.poisson(2000)),
                float(np.random.beta(5, 1) * 100),
                float(np.random.poisson(20)),
                float(np.random.poisson(25)),
                float(np.random.poisson(30)),
                float(np.random.normal(20000, 5000)),
                float(np.random.poisson(50)),
                float(np.random.poisson(20))
            ]
            X_train.append(features)
            y_train.append(1)
        
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        self.isolation_forest.fit(X_scaled)
        
        self.random_forest = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.random_forest.fit(X_scaled, y_train)
        
        self.model_accuracy = self.random_forest.score(X_scaled, y_train)
        self.is_trained = True
        
        print(f"✅ ML models loaded: {self.model_accuracy:.2%} accuracy")
    
    def extract_features(self, behavioral_data: Dict) -> np.array:
        features = [
            float(behavioral_data.get('typing_speed_avg', 200)),
            float(behavioral_data.get('typing_speed_std', 30)),
            float(behavioral_data.get('typing_consistency', 85)),
            float(behavioral_data.get('session_duration', 10)),
            float(behavioral_data.get('keystroke_count', 100)),
            float(behavioral_data.get('error_rate', 5)),
            float(behavioral_data.get('paste_events', 1)),
            float(behavioral_data.get('copy_events', 2)),
            float(behavioral_data.get('tab_switches', 2)),
            float(behavioral_data.get('mouse_distance', 5000)),
            float(behavioral_data.get('command_frequency', 5)),
            float(behavioral_data.get('focus_losses', 1))
        ]
        return np.array(features).reshape(1, -1)
    
    def predict(self, behavioral_data: Dict) -> Tuple[bool, float, float, List[str]]:
        if not self.is_trained:
            return False, 0.0, 0.0, ["Model not trained"]
        
        try:
            features = self.extract_features(behavioral_data)
            features_scaled = self.scaler.transform(features)
            
            if_pred = self.isolation_forest.predict(features_scaled)[0]
            if_score = float(self.isolation_forest.score_samples(features_scaled)[0])
            
            rf_proba = self.random_forest.predict_proba(features_scaled)[0]
            rf_pred = self.random_forest.predict(features_scaled)[0]
            rf_confidence = float(max(rf_proba))
            
            is_anomaly = bool(if_pred == -1 or rf_pred == 1)
            anomaly_score = float(abs(if_score) * rf_confidence * 100)
            
            reasons = self._get_anomaly_reasons(behavioral_data)
            
            return is_anomaly, anomaly_score, rf_confidence, reasons
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0, 0.0, [f"Error: {str(e)}"]
    
    def _get_anomaly_reasons(self, data: Dict) -> List[str]:
        reasons = []
        if data.get('typing_speed_avg', 200) > 400:
            reasons.append(f"Unusual typing speed: {data['typing_speed_avg']:.0f}ms")
        if data.get('typing_consistency', 85) < 50:
            reasons.append(f"Erratic typing pattern: {data['typing_consistency']:.0f}%")
        if data.get('paste_events', 1) > 10:
            reasons.append(f"Excessive paste events: {data['paste_events']}")
        if data.get('copy_events', 2) > 15:
            reasons.append(f"Excessive copy events: {data['copy_events']}")
        if data.get('tab_switches', 2) > 20:
            reasons.append(f"Frequent tab switching: {data['tab_switches']}")
        if data.get('session_duration', 10) > 120:
            reasons.append(f"Long session: {data['session_duration']:.0f} minutes")
        return reasons if reasons else ["Normal behavior"]


# ==================== USER PROFILING ====================

class UserBehaviorProfile:
    """Tracks user behavioral profiles with MongoDB persistence"""
    
    def __init__(self, user_id: str, db: MongoDB, user_data: dict = None):
        self.user_id = user_id
        self.db = db
        self.user_data = user_data or {}
        self.keystroke_timings = []
        self.error_count = 0
        self.total_keystrokes = 0
        self.paste_events = 0
        self.copy_events = 0
        self.tab_switches = 0
        self.focus_losses = 0
        self.mouse_movements = []
        self.commands = defaultdict(int)
        self.session_start = datetime.now()
        self.last_active = datetime.now()
        self.anomaly_count = self.user_data.get('anomaly_count', 0)
        self.risk_score = self.user_data.get('risk_score', 0)
        self.alert_history = []
        self.login_ip = "127.0.0.1"
        self.login_time = datetime.now()
        self.device = "Web"
    
    def update(self, event_type: str, event_data: Dict):
        self.last_active = datetime.now()
        
        if event_type == 'keystroke':
            self.total_keystrokes += 1
            if 'interval' in event_data:
                self.keystroke_timings.append(float(event_data['interval']))
            if event_data.get('error', False):
                self.error_count += 1
        elif event_type == 'paste':
            self.paste_events += 1
        elif event_type == 'copy':
            self.copy_events += 1
        elif event_type == 'tab_switch':
            self.tab_switches += 1
        elif event_type == 'focus_loss':
            self.focus_losses += 1
        
        max_history = 1000
        if len(self.keystroke_timings) > max_history:
            self.keystroke_timings = self.keystroke_timings[-max_history:]
    
    def get_behavioral_features(self) -> Dict:
        features = {}
        
        if self.keystroke_timings:
            recent = self.keystroke_timings[-200:]
            features['typing_speed_avg'] = float(np.mean(recent))
            features['typing_speed_std'] = float(np.std(recent))
            features['typing_consistency'] = float(100 - min(100, features['typing_speed_std'] / 2))
        else:
            features['typing_speed_avg'] = 200.0
            features['typing_speed_std'] = 30.0
            features['typing_consistency'] = 85.0
        
        features['session_duration'] = float((datetime.now() - self.session_start).total_seconds() / 60)
        features['keystroke_count'] = float(self.total_keystrokes)
        
        if self.total_keystrokes > 0:
            features['error_rate'] = float((self.error_count / self.total_keystrokes) * 100)
        else:
            features['error_rate'] = 5.0
        
        features['paste_events'] = float(self.paste_events)
        features['copy_events'] = float(self.copy_events)
        features['tab_switches'] = float(self.tab_switches)
        features['focus_losses'] = float(self.focus_losses)
        features['mouse_distance'] = float(len(self.mouse_movements) * 100)
        features['command_frequency'] = float(sum(self.commands.values()))
        
        return features
    
    def get_risk_summary(self) -> Dict:
        return {
            'user_id': self.user_id,
            'full_name': self.user_data.get('full_name', self.user_id),
            'role': self.user_data.get('role', 'user'),
            'avatar': self.user_data.get('avatar', '👤'),
            'risk_score': round(self.risk_score, 2),
            'risk_level': self.user_data.get('risk_level', 'LOW'),
            'anomaly_count': self.anomaly_count,
            'device': self.device,
            'last_active': self.last_active.isoformat()
        }


# ==================== ML MONITORING SYSTEM ====================

class MLMonitoringSystem:
    """Main ML monitoring system with MongoDB persistence"""
    
    def __init__(self, dashboard_manager, db: MongoDB):
        self.model = SecureHackMLModel()
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.dashboard = dashboard_manager
        self.db = db
        self.alert_thresholds = {
            'CRITICAL': 80,
            'HIGH': 60,
            'MEDIUM': 40,
            'LOW': 20
        }
        self._load_active_sessions()
    
    def _load_active_sessions(self):
        try:
            active_sessions = self.db.get_active_sessions()
            for session in active_sessions:
                self.active_sessions[session['session_id']] = {
                    'user_id': session['user_id'],
                    'start_time': session.get('login_time', datetime.now()),
                    'events': [],
                    'alert_count': session.get('alert_count', 0)
                }
        except:
            pass
    
    def get_or_create_profile(self, user_id: str, user_data: dict = None, ip: str = "127.0.0.1", device: str = "Web") -> UserBehaviorProfile:
        if user_id not in self.user_profiles:
            profile = UserBehaviorProfile(user_id, self.db, user_data)
            profile.login_ip = ip
            profile.login_time = datetime.now()
            profile.device = device
            self.user_profiles[user_id] = profile
        return self.user_profiles[user_id]
    
    async def track_event(self, session_id: str, user_id: str, event_data: Dict, ip: str = "127.0.0.1", device: str = "Web"):
        profile = self.get_or_create_profile(user_id, ip=ip, device=device)
        event_type = event_data.get('type', 'unknown')
        profile.update(event_type, event_data)
        
        if session_id not in self.active_sessions:
            # Check if session already exists in DB
            existing_session = None  # self.db.get_session(session_id)
            if existing_session:
                self.active_sessions[session_id] = {
                    'user_id': existing_session['user_id'],
                    'start_time': existing_session.get('login_time', datetime.now()),
                    'events': [],
                    'alert_count': existing_session.get('alert_count', 0)
                }
            else:
                self.active_sessions[session_id] = {
                    'user_id': user_id,
                    'start_time': datetime.now(),
                    'events': [],
                    'alert_count': 0
                }
                self.db.create_session({
                    'session_id': session_id,
                    'user_id': user_id,
                    'login_time': datetime.now(),
                    'active': True,
                    'alert_count': 0,
                    'ip': ip,
                    'device': device
                })
        
        session = self.active_sessions[session_id]
        session['events'].append({'timestamp': datetime.now().isoformat(), 'type': event_type})
        
        # Get active users for this session
        active_users = self.get_all_active_users()
        
        # Run ML analysis periodically
        if len(session['events']) % 10 == 0:
            features = profile.get_behavioral_features()
            is_anomaly, score, confidence, reasons = self.model.predict(features)
            
            if is_anomaly:
                profile.anomaly_count += 1
                profile.risk_score = score
                
                if score >= self.alert_thresholds['CRITICAL']:
                    severity = 'CRITICAL'
                elif score >= self.alert_thresholds['HIGH']:
                    severity = 'HIGH'
                elif score >= self.alert_thresholds['MEDIUM']:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Update user in DB
                self.db.update_user(user_id, {
                    'risk_score': score,
                    'risk_level': severity,
                    'anomaly_count': profile.anomaly_count
                })
                
                # Log with active users
                logger.anomaly_detected(user_id, score, reasons, severity)
                
                alert = {
                    'title': f"Anomaly Detected - {user_id}",
                    'severity': severity,
                    'score': round(score, 2),
                    'user_id': user_id,
                    'reasons': reasons,
                    'active_users': active_users
                }
                
                await self.dashboard.alert_manager.send_alert(alert)
                
                session['alert_count'] += 1
                self.db.update_session(session_id, {'alert_count': session['alert_count']})
        
        await self._update_dashboard_metrics()
    
    def get_all_active_users(self) -> List[str]:
        """Get all active users across all sessions"""
        users = set()
        for session in self.active_sessions.values():
            users.add(session['user_id'])
        return list(users)
    
    async def _update_dashboard_metrics(self):
        active_users_list = self.get_all_active_users()
        
        metrics = {
            'active_users': len(active_users_list),
            'active_sessions': len(self.active_sessions),
            'total_alerts': len(self.dashboard.alert_manager.alert_history),
            'avg_risk_score': float(np.mean([p.risk_score for p in self.user_profiles.values()])) if self.user_profiles else 0,
            'critical_alerts': len([a for a in self.dashboard.alert_manager.alert_history if a.get('severity') == 'CRITICAL']),
            'high_alerts': len([a for a in self.dashboard.alert_manager.alert_history if a.get('severity') == 'HIGH']),
            'active_users_list': active_users_list
        }
        
        # Log system stats periodically
        if len(self.user_profiles) > 0:
            logger.system_stats(
                len(active_users_list),
                len(self.active_sessions),
                len(self.dashboard.alert_manager.alert_history),
                active_users_list
            )
        
        await self.dashboard.broadcast_metrics(metrics)
    
    def get_user_risk(self, user_id: str) -> Dict:
        if user_id not in self.user_profiles:
            return {'risk_score': 0, 'risk_level': 'LOW', 'is_anomaly': False, 'reasons': []}
        
        profile = self.user_profiles[user_id]
        features = profile.get_behavioral_features()
        is_anomaly, score, confidence, reasons = self.model.predict(features)
        
        if score >= self.alert_thresholds['CRITICAL']:
            level = 'CRITICAL'
        elif score >= self.alert_thresholds['HIGH']:
            level = 'HIGH'
        elif score >= self.alert_thresholds['MEDIUM']:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'user_id': user_id,
            'risk_score': round(score, 2),
            'risk_level': level,
            'is_anomaly': bool(is_anomaly),
            'reasons': reasons,
            'profile_summary': profile.get_risk_summary()
        }
    
    def get_dashboard_data(self) -> Dict:
        db_stats = self.db.get_dashboard_stats()
        active_users_list = self.get_all_active_users()
        
        # Get full user details for active users
        active_users_details = []
        for username in active_users_list:
            user = self.db.get_user(username)
            if user:
                active_users_details.append({
                    'username': username,
                    'name': user.get('full_name', username),
                    'role': user.get('role', 'user'),
                    'avatar': user.get('avatar', '👤'),
                    'color': user.get('color', '#667eea'),
                    'risk_level': user.get('risk_level', 'LOW')
                })
        
        return {
            'stats': {
                'total_users': db_stats.get('total_users', 0),
                'active_sessions': db_stats.get('active_sessions', 0),
                'total_alerts': db_stats.get('total_alerts', 0),
                'avg_risk': float(np.mean([p.risk_score for p in self.user_profiles.values()])) if self.user_profiles else 0,
                'risk_distribution': db_stats.get('risk_distribution', {}),
                'active_threats': db_stats.get('risk_distribution', {}).get('HIGH', 0) + db_stats.get('risk_distribution', {}).get('CRITICAL', 0),
                'active_users_list': active_users_list,
                'active_users_count': len(active_users_list),
                'active_users_details': active_users_details
            },
            'recent_alerts': self.dashboard.alert_manager.get_recent_alerts(20),
            'recent_logins': db_stats.get('recent_logins', []),
            'timestamp': datetime.now().isoformat()
        }


# ==================== ALERT MANAGER ====================

class AlertManager:
    """Alert manager with MongoDB storage"""
    
    def __init__(self, db: MongoDB):
        self.db = db
        self.alert_callbacks = []
        self.alert_levels = {
            'CRITICAL': {'color': '#ef4444', 'icon': '🔥'},
            'HIGH': {'color': '#f97316', 'icon': '⚠️'},
            'MEDIUM': {'color': '#eab308', 'icon': '⚡'},
            'LOW': {'color': '#10b981', 'icon': 'ℹ️'}
        }
        self.alert_history = []
    
    def register_callback(self, callback):
        self.alert_callbacks.append(callback)
    
    async def send_alert(self, alert: Dict) -> Optional[str]:
        alert['id'] = secrets.token_hex(4)
        alert['timestamp'] = datetime.now()
        alert_id = self.db.create_alert(alert)
        self.alert_history.append(alert)
        
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except:
                pass
        
        return alert_id
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        return self.alert_history[-limit:] if self.alert_history else []


# ==================== DASHBOARD MANAGER ====================

class DashboardManager:
    """Manages real-time dashboard connections"""
    
    def __init__(self, db: MongoDB):
        self.active_dashboards: Set[WebSocket] = set()
        self.alert_manager = AlertManager(db)
        self.metrics_history = defaultdict(list)
        self.db = db
    
    async def register_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        self.active_dashboards.add(websocket)
        logger.dashboard_connected()
    
    def unregister_dashboard(self, websocket: WebSocket):
        self.active_dashboards.discard(websocket)
        logger.dashboard_disconnected()
    
    async def broadcast_metrics(self, metrics: Dict):
        timestamp = datetime.now().isoformat()
        for key, value in metrics.items():
            self.metrics_history[key].append({'timestamp': timestamp, 'value': value})
            if len(self.metrics_history[key]) > 100:
                self.metrics_history[key] = self.metrics_history[key][-100:]
        
        disconnected = set()
        for dashboard in self.active_dashboards:
            try:
                await dashboard.send_json({
                    'type': 'metrics_update',
                    'data': metrics,
                    'timestamp': timestamp
                })
            except:
                disconnected.add(dashboard)
        
        for d in disconnected:
            self.active_dashboards.discard(d)
    
    async def broadcast_alert(self, alert: Dict):
        disconnected = set()
        for dashboard in self.active_dashboards:
            try:
                await dashboard.send_json({'type': 'new_alert', 'data': alert})
            except:
                disconnected.add(dashboard)
        for d in disconnected:
            self.active_dashboards.discard(d)


# ==================== FASTAPI APP INITIALIZATION ====================

db = MongoDB()
dashboard_manager = DashboardManager(db)
ml_system = MLMonitoringSystem(dashboard_manager, db)

app = FastAPI(title="SecureHack AI - Shareable Multi-User Login System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions = {}

# ==================== HELPER FUNCTIONS ====================

def detect_device(user_agent: str) -> str:
    """Detect device type from user agent"""
    user_agent = user_agent.lower()
    if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        return "📱 Mobile"
    elif 'tablet' in user_agent or 'ipad' in user_agent:
        return "📟 Tablet"
    else:
        return "💻 Desktop"

# ==================== API ENDPOINTS ====================

@app.post("/api/auth/login")
async def ml_login(request: Request, credentials: dict):
    username = credentials.get('username', '')
    password = credentials.get('password', '')
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'Unknown')
    device = detect_device(user_agent)
    
    if not username or not password:
        raise HTTPException(status_code=401, detail="Username and password required")
    
    # Authenticate user
    user = db.authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    profile = ml_system.get_or_create_profile(username, user, client_ip, device)
    features = profile.get_behavioral_features()
    is_anomaly, score, confidence, reasons = ml_system.model.predict(features)
    
    risk_score = float(min(100, score))
    session_token = secrets.token_urlsafe(32)
    session_id = secrets.token_hex(8)
    
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    # Log login with device info
    active_users = ml_system.get_all_active_users()
    logger.user_login(username, risk_score, risk_level, device, client_ip)
    
    # Store session in MongoDB
    db.create_session({
        'session_id': session_id,
        'user_id': username,
        'login_time': datetime.now(),
        'login_ip': client_ip,
        'device': device,
        'user_agent': user_agent,
        'active': True,
        'session_token': session_token,
        'risk_score': risk_score,
        'risk_level': risk_level
    })
    
    # Update active sessions in memory
    ml_system.active_sessions[session_id] = {
        'user_id': username,
        'start_time': datetime.now(),
        'events': [],
        'alert_count': 0,
        'device': device
    }
    
    sessions[session_token] = {
        'username': username,
        'session_id': session_id,
        'login_time': datetime.now().isoformat(),
        'ip': client_ip,
        'device': device
    }
    
    return JSONResponse(content={
        'success': True,
        'session_token': session_token,
        'session_id': session_id,
        'user': {
            'id': username,
            'username': username,
            'name': user.get('full_name', username.title()),
            'initials': username[:2].upper() if username else 'U',
            'role': user.get('role', 'user'),
            'avatar': user.get('avatar', '👤'),
            'color': user.get('color', '#667eea'),
            'risk_level': risk_level,
            'risk_score': risk_score
        },
        'ml_assessment': {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'is_anomaly': bool(is_anomaly),
            'reasons': reasons
        },
        'device': device,
        'active_users': active_users,
        'active_users_count': len(active_users)
    })


@app.get("/api/active-users")
async def get_active_users():
    """Get list of currently active users"""
    active_users = ml_system.get_all_active_users()
    user_details = []
    
    for username in active_users:
        user = db.get_user(username)
        if user:
            user_details.append({
                'username': username,
                'name': user.get('full_name', username),
                'role': user.get('role', 'user'),
                'avatar': user.get('avatar', '👤'),
                'risk_level': user.get('risk_level', 'LOW')
            })
    
    return JSONResponse(content={
        'active_users': user_details,
        'count': len(user_details),
        'usernames': active_users
    })


@app.get("/api/users")
async def get_all_users():
    """Get all registered users"""
    users = db.get_all_users()
    user_list = []
    for user in users:
        user_list.append({
            'username': user.get('username'),
            'name': user.get('full_name'),
            'role': user.get('role'),
            'avatar': user.get('avatar', '👤'),
            'color': user.get('color', '#667eea'),
            'risk_level': user.get('risk_level'),
            'password': user.get('password')  # Include for sharing
        })
    return JSONResponse(content={'users': user_list, 'count': len(user_list)})


@app.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get dashboard data from MongoDB"""
    return JSONResponse(content=ml_system.get_dashboard_data())


@app.get("/api/health")
async def health_check():
    active_users = ml_system.get_all_active_users()
    return JSONResponse(content={
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'ml_model': 'loaded' if ml_system.model.is_trained else 'not_loaded',
        'mongodb': 'connected' if db.is_connected else 'disconnected',
        'registered_users': len(db.get_all_users()),
        'active_users': len(active_users),
        'active_users_list': active_users,
        'active_sessions': len(ml_system.active_sessions),
        'total_alerts': len(dashboard_manager.alert_manager.alert_history)
    })


# ==================== WEBSOCKET ENDPOINTS ====================

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await dashboard_manager.register_dashboard(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == 'ping':
                await websocket.send_json({'type': 'pong'})
    except:
        dashboard_manager.unregister_dashboard(websocket)


# ==================== SHAREABLE CREDENTIALS PAGE ====================

@app.get("/share", response_class=HTMLResponse)
async def share_credentials(request: Request):
    """Shareable page with all user credentials"""
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'Unknown')
    device = detect_device(user_agent)
    logger.share_link_accessed(client_ip, device)
    
    users = db.get_all_users()
    
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>SecureHack AI - Shareable Credentials</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: white;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: rgba(255,255,255,0.9);
            font-size: 16px;
        }
        
        .share-badge {
            background: rgba(255,255,255,0.2);
            backdrop-filter: blur(10px);
            border-radius: 40px;
            padding: 12px 24px;
            display: inline-block;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.3);
        }
        
        .share-badge i {
            color: #ffd700;
            margin-right: 8px;
        }
        
        .stats-card {
            background: white;
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--primary);
        }
        
        .stat-label {
            color: #64748b;
            font-size: 13px;
            margin-top: 5px;
        }
        
        .users-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .user-card {
            background: white;
            border-radius: 20px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            transition: transform 0.3s;
            border: 2px solid transparent;
        }
        
        .user-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }
        
        .user-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .user-avatar {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
            color: white;
        }
        
        .user-info h3 {
            font-size: 18px;
            margin-bottom: 4px;
        }
        
        .user-role {
            font-size: 13px;
            color: #64748b;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .credentials {
            background: #f8fafc;
            border-radius: 12px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .cred-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .cred-row:last-child {
            border-bottom: none;
        }
        
        .cred-label {
            color: #64748b;
            font-size: 13px;
        }
        
        .cred-value {
            font-family: monospace;
            font-weight: 600;
            background: #e2e8f0;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .copy-btn {
            background: none;
            border: none;
            color: var(--primary);
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .copy-btn:hover {
            background: #e2e8f0;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            margin-top: 8px;
        }
        
        .login-btn {
            display: block;
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            margin-top: 15px;
            transition: opacity 0.3s;
        }
        
        .login-btn:hover {
            opacity: 0.9;
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
        }
        
        .footer a {
            color: white;
            text-decoration: none;
            margin: 0 10px;
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--success);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            display: none;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
        }
        
        @media (max-width: 640px) {
            .users-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="share-badge">
                <i class="fas fa-share-alt"></i>
                Shareable Credentials - Send this link to your friends!
            </div>
            <h1><i class="fas fa-users"></i> SecureHack AI Demo Accounts</h1>
            <p>Click on any user to auto-fill credentials • Copy passwords with one click</p>
        </div>
        
        <div class="stats-card">
            <div class="stats-grid">
                <div>
                    <div class="stat-value">6</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div>
                    <div class="stat-value" id="activeCount">0</div>
                    <div class="stat-label">Currently Online</div>
                </div>
                <div>
                    <div class="stat-value" id="alertCount">0</div>
                    <div class="stat-label">Security Alerts</div>
                </div>
            </div>
        </div>
        
        <div class="users-grid" id="usersGrid">
    """
    
    for user in users:
        color = user.get('color', '#667eea')
        html += f"""
            <div class="user-card" style="border-color: {color}20;">
                <div class="user-header">
                    <div class="user-avatar" style="background: {color};">
                        {user.get('avatar', '👤')}
                    </div>
                    <div class="user-info">
                        <h3>{user.get('full_name')}</h3>
                        <div class="user-role">
                            <i class="fas fa-tag"></i> {user.get('role')}
                        </div>
                        <span class="risk-badge" style="background: {color}20; color: {color};">
                            {user.get('risk_level')} Risk
                        </span>
                    </div>
                </div>
                
                <div class="credentials">
                    <div class="cred-row">
                        <span class="cred-label"><i class="fas fa-user"></i> Username</span>
                        <span>
                            <span class="cred-value">{user.get('username')}</span>
                            <button class="copy-btn" onclick="copyToClipboard('{user.get('username')}')">
                                <i class="far fa-copy"></i>
                            </button>
                        </span>
                    </div>
                    <div class="cred-row">
                        <span class="cred-label"><i class="fas fa-lock"></i> Password</span>
                        <span>
                            <span class="cred-value">{user.get('password')}</span>
                            <button class="copy-btn" onclick="copyToClipboard('{user.get('password')}')">
                                <i class="far fa-copy"></i>
                            </button>
                        </span>
                    </div>
                </div>
                
                <a href="/?username={user.get('username')}&password={user.get('password')}" class="login-btn" style="background: {color};">
                    <i class="fas fa-sign-in-alt"></i> Login as {user.get('username')}
                </a>
            </div>
        """
    
    html += """
        </div>
        
        <div class="footer">
            <a href="/"><i class="fas fa-arrow-left"></i> Back to Login</a>
            <a href="/dashboard"><i class="fas fa-chart-pie"></i> Live Dashboard</a>
            <a href="#" onclick="copyShareLink()"><i class="fas fa-share-alt"></i> Copy Share Link</a>
        </div>
    </div>
    
    <div class="toast" id="toast">Copied to clipboard!</div>
    
    <script>
        // Copy to clipboard function
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                const toast = document.getElementById('toast');
                toast.style.display = 'block';
                setTimeout(() => {
                    toast.style.display = 'none';
                }, 2000);
            });
        }
        
        // Copy share link
        function copyShareLink() {
            const link = window.location.href;
            copyToClipboard(link);
        }
        
        // Auto-fill login from URL params
        const urlParams = new URLSearchParams(window.location.search);
        const username = urlParams.get('username');
        const password = urlParams.get('password');
        
        if (username && password) {
            // Store in sessionStorage and redirect to login
            sessionStorage.setItem('auto_login', JSON.stringify({username, password}));
            window.location.href = '/';
        }
        
        // Fetch live stats
        async function fetchStats() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                document.getElementById('activeCount').textContent = data.active_users || 0;
                document.getElementById('alertCount').textContent = data.total_alerts || 0;
            } catch (error) {
                console.error('Error fetching stats:', error);
            }
        }
        
        fetchStats();
        setInterval(fetchStats, 3000);
    </script>
</body>
</html>
    """
    
    return HTMLResponse(content=html)


# ==================== MAIN LOGIN PAGE (Modified to accept URL params) ====================

@app.get("/", response_class=HTMLResponse)
async def get_login_page(request: Request):
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>SecureHack AI - Multi-User Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1a1a2e;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
        }
        
        .container {
            width: 100%;
            max-width: 400px;
            margin: 0 auto;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            text-align: center;
            margin-bottom: 24px;
        }
        
        .logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 16px;
            color: white;
            font-size: 30px;
            transform: rotate(5deg);
            transition: transform 0.3s;
        }
        
        .logo:hover {
            transform: rotate(0deg) scale(1.1);
        }
        
        h1 {
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 4px;
        }
        
        .share-badge {
            background: rgba(255, 215, 0, 0.2);
            color: #b8860b;
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 13px;
            margin: 10px 0;
            display: inline-block;
            border: 1px solid #ffd700;
        }
        
        .share-badge i {
            color: #ffd700;
        }
        
        .users-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            margin: 20px 0;
        }
        
        .user-chip {
            background: #f1f5f9;
            padding: 8px 4px;
            border-radius: 30px;
            text-align: center;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            border: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .user-chip:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .user-chip.selected {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
        }
        
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 6px;
            font-size: 13px;
            font-weight: 600;
            color: #334155;
        }
        
        .input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }
        
        .input-wrapper i {
            position: absolute;
            left: 12px;
            color: #94a3b8;
            font-size: 16px;
        }
        
        .input-wrapper input {
            width: 100%;
            padding: 14px 14px 14px 40px;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            font-size: 15px;
            transition: all 0.3s;
            -webkit-appearance: none;
        }
        
        .input-wrapper input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        
        .btn-login {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin: 20px 0 16px;
            transition: all 0.3s;
        }
        
        .btn-login:active {
            transform: scale(0.98);
        }
        
        .btn-login:disabled {
            opacity: 0.7;
            transform: none;
        }
        
        .btn-login.loading {
            position: relative;
            color: transparent;
        }
        
        .btn-login.loading::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            top: 50%;
            left: 50%;
            margin-left: -10px;
            margin-top: -10px;
            border: 3px solid white;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .active-users {
            background: #f1f5f9;
            border-radius: 12px;
            padding: 12px;
            margin-top: 16px;
        }
        
        .active-users-title {
            font-size: 13px;
            font-weight: 600;
            color: #334155;
            margin-bottom: 8px;
        }
        
        .active-users-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        
        .active-user-tag {
            background: white;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .user-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            display: inline-block;
        }
        
        .footer {
            text-align: center;
            margin-top: 20px;
            color: white;
            font-size: 13px;
        }
        
        .footer a {
            color: white;
            text-decoration: none;
            margin: 0 8px;
            opacity: 0.9;
        }
        
        .footer a:hover {
            opacity: 1;
            text-decoration: underline;
        }
        
        .alert {
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 16px;
            font-size: 13px;
            display: none;
        }
        
        .alert.error {
            background: #fee2e2;
            color: #dc2626;
            border: 1px solid #fecaca;
            display: block;
        }
        
        .alert.success {
            background: #d1fae5;
            color: #059669;
            border: 1px solid #a7f3d0;
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="logo">
                    <i class="fas fa-shield-halved"></i>
                </div>
                <h1>SecureHack AI</h1>
                <div class="share-badge">
                    <i class="fas fa-share-alt"></i>
                    <a href="/share" style="color: #b8860b; text-decoration: none;">Click here for shareable credentials →</a>
                </div>
            </div>
            
            <div class="users-grid" id="userGrid">
                <div class="user-chip" data-username="admin" data-password="admin123">👑 Admin</div>
                <div class="user-chip" data-username="alice" data-password="alice123">👩‍💻 Alice</div>
                <div class="user-chip" data-username="bob" data-password="bob123">👨‍💻 Bob</div>
                <div class="user-chip" data-username="charlie" data-password="charlie123">📊 Charlie</div>
                <div class="user-chip" data-username="david" data-password="david123">💼 David</div>
                <div class="user-chip" data-username="eve" data-password="eve123">🎓 Eve</div>
            </div>
            
            <div class="alert error" id="errorMsg"></div>
            <div class="alert success" id="successMsg"></div>
            
            <form id="loginForm">
                <div class="input-group">
                    <label><i class="far fa-user"></i> Username</label>
                    <div class="input-wrapper">
                        <i class="fas fa-user"></i>
                        <input type="text" id="username" placeholder="Enter username" value="admin">
                    </div>
                </div>
                
                <div class="input-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <div class="input-wrapper">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" placeholder="Enter password" value="admin123">
                    </div>
                </div>
                
                <button type="submit" class="btn-login" id="loginBtn">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>
            
            <div class="active-users">
                <div class="active-users-title">
                    <i class="fas fa-circle" style="color: #10b981; font-size: 8px;"></i>
                    Currently Online
                </div>
                <div class="active-users-list" id="activeUsersList">
                    <span style="color: #94a3b8;">Loading...</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <a href="/share"><i class="fas fa-share-alt"></i> Share Credentials</a>
            <a href="/dashboard"><i class="fas fa-chart-pie"></i> Dashboard</a>
        </div>
    </div>
    
    <script>
        // Auto-fill from URL params (from share link)
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('username') && urlParams.has('password')) {
            document.getElementById('username').value = urlParams.get('username');
            document.getElementById('password').value = urlParams.get('password');
            
            // Highlight the selected user
            document.querySelectorAll('.user-chip').forEach(chip => {
                if (chip.dataset.username === urlParams.get('username')) {
                    chip.classList.add('selected');
                }
            });
        }
        
        // Select user chip
        document.querySelectorAll('.user-chip').forEach(chip => {
            chip.addEventListener('click', function() {
                document.querySelectorAll('.user-chip').forEach(c => c.classList.remove('selected'));
                this.classList.add('selected');
                document.getElementById('username').value = this.dataset.username;
                document.getElementById('password').value = this.dataset.password;
            });
        });
        
        // Login handler
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('loginBtn');
            
            btn.classList.add('loading');
            btn.disabled = true;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                    sessionStorage.setItem('session_token', data.session_token);
                    
                    document.getElementById('successMsg').textContent = 
                        `✅ Welcome ${data.user.name}! Risk Score: ${data.ml_assessment.risk_score}`;
                    document.getElementById('successMsg').style.display = 'block';
                    document.getElementById('errorMsg').style.display = 'none';
                    
                    setTimeout(() => {
                        window.location.href = '/dashboard';
                    }, 1500);
                } else {
                    throw new Error(data.detail || 'Invalid credentials');
                }
            } catch (error) {
                document.getElementById('errorMsg').textContent = error.message;
                document.getElementById('errorMsg').style.display = 'block';
                document.getElementById('successMsg').style.display = 'none';
            } finally {
                btn.classList.remove('loading');
                btn.disabled = false;
            }
        });
        
        // Fetch active users
        async function fetchActiveUsers() {
            try {
                const response = await fetch('/api/active-users');
                const data = await response.json();
                
                const listContainer = document.getElementById('activeUsersList');
                if (data.active_users && data.active_users.length > 0) {
                    listContainer.innerHTML = data.active_users.map(u => 
                        `<span class="active-user-tag">
                            <span class="user-dot"></span>
                            ${u.name || u.username}
                        </span>`
                    ).join('');
                } else {
                    listContainer.innerHTML = '<span style="color: #94a3b8;">No active users</span>';
                }
            } catch (error) {
                console.error('Error fetching active users:', error);
            }
        }
        
        fetchActiveUsers();
        setInterval(fetchActiveUsers, 3000);
    </script>
</body>
</html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>SecureHack AI - Live Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --darker: #0b1120;
            --light: #f8fafc;
            --gray: #94a3b8;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--dark);
            color: var(--light);
            padding: 16px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: var(--darker);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            border: 1px solid #334155;
        }
        
        .header h1 {
            font-size: 24px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .share-badge {
            background: rgba(255, 215, 0, 0.1);
            border: 1px solid #ffd700;
            color: #ffd700;
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 14px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--darker);
            border-radius: 16px;
            padding: 20px;
            border: 1px solid #334155;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 4px;
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 13px;
        }
        
        .users-section {
            background: var(--darker);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #334155;
        }
        
        .section-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            font-size: 16px;
            font-weight: 600;
        }
        
        .users-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
        }
        
        .user-card {
            background: #1e293b;
            border-radius: 12px;
            padding: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            border: 1px solid #334155;
            transition: transform 0.2s;
        }
        
        .user-card:hover {
            transform: translateY(-2px);
            border-color: var(--primary);
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 20px;
        }
        
        .user-info {
            flex: 1;
        }
        
        .user-name {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 2px;
        }
        
        .user-role {
            font-size: 11px;
            color: var(--gray);
        }
        
        .charts-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .chart-container {
            background: var(--darker);
            border-radius: 20px;
            padding: 20px;
            border: 1px solid #334155;
        }
        
        .alerts-section {
            background: var(--darker);
            border-radius: 20px;
            padding: 20px;
            border: 1px solid #334155;
        }
        
        .alert-item {
            background: #1e293b;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 8px;
            border-left: 4px solid;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .footer {
            text-align: center;
            margin-top: 20px;
            color: var(--gray);
            font-size: 13px;
        }
        
        .footer a {
            color: var(--primary);
            text-decoration: none;
            margin: 0 8px;
        }
        
        @media (max-width: 768px) {
            .charts-row {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-chart-pie"></i> Live Multi-User Dashboard</h1>
            <div class="share-badge">
                <i class="fas fa-share-alt"></i>
                <a href="/share" style="color: #ffd700; text-decoration: none;">Share Credentials</a>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalUsers">0</div>
                <div class="stat-label">Registered Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="activeUsers">0</div>
                <div class="stat-label">Currently Online</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalAlerts">0</div>
                <div class="stat-label">Security Alerts</div>
            </div>
        </div>
        
        <div class="users-section">
            <div class="section-title">
                <span><i class="fas fa-users"></i> Online Now</span>
                <span style="color: var(--gray);" id="activeCount">0 online</span>
            </div>
            <div class="users-grid" id="activeUsersGrid">
                <div style="color: var(--gray); text-align: center; padding: 20px;">Loading...</div>
            </div>
        </div>
        
        <div class="charts-row">
            <div class="chart-container">
                <canvas id="riskChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="userChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="section-title">
                <span><i class="fas fa-bell"></i> Recent Alerts</span>
            </div>
            <div id="alertsList">
                <div style="color: var(--gray); text-align: center; padding: 20px;">No recent alerts</div>
            </div>
        </div>
        
        <div class="footer">
            <a href="/"><i class="fas fa-arrow-left"></i> Login</a>
            <a href="/share"><i class="fas fa-share-alt"></i> Share Credentials</a>
        </div>
    </div>
    
    <script>
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        const userCtx = document.getElementById('userChart').getContext('2d');
        
        const riskChart = new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8' } }
                }
            }
        });
        
        const userChart = new Chart(userCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Active Users',
                    data: [],
                    backgroundColor: '#667eea',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                    x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                }
            }
        });
        
        async function fetchDashboardData() {
            try {
                const response = await fetch('/api/dashboard/data');
                const data = await response.json();
                
                document.getElementById('totalUsers').textContent = data.stats.total_users || 0;
                document.getElementById('activeUsers').textContent = data.stats.active_users_count || 0;
                document.getElementById('totalAlerts').textContent = data.stats.total_alerts || 0;
                document.getElementById('activeCount').textContent = `${data.stats.active_users_count || 0} online`;
                
                if (data.stats.risk_distribution) {
                    riskChart.data.datasets[0].data = [
                        data.stats.risk_distribution.LOW || 0,
                        data.stats.risk_distribution.MEDIUM || 0,
                        data.stats.risk_distribution.HIGH || 0,
                        data.stats.risk_distribution.CRITICAL || 0
                    ];
                    riskChart.update();
                }
                
                const activeUsersGrid = document.getElementById('activeUsersGrid');
                if (data.stats.active_users_details && data.stats.active_users_details.length > 0) {
                    activeUsersGrid.innerHTML = data.stats.active_users_details.map(user => `
                        <div class="user-card">
                            <div class="user-avatar" style="background: ${user.color}20; color: ${user.color};">${user.avatar}</div>
                            <div class="user-info">
                                <div class="user-name">${user.name}</div>
                                <div class="user-role">${user.role}</div>
                            </div>
                        </div>
                    `).join('');
                } else {
                    activeUsersGrid.innerHTML = '<div style="color: var(--gray); text-align: center; padding: 20px;">No active users</div>';
                }
                
                const alertsList = document.getElementById('alertsList');
                if (data.recent_alerts && data.recent_alerts.length > 0) {
                    alertsList.innerHTML = data.recent_alerts.slice(0, 5).map(alert => {
                        const severity = alert.severity.toLowerCase();
                        const color = severity === 'critical' ? '#ef4444' : 
                                     severity === 'high' ? '#f97316' : 
                                     severity === 'medium' ? '#eab308' : '#10b981';
                        return `
                            <div class="alert-item" style="border-color: ${color}">
                                <div>
                                    <div style="font-weight: 600;">${alert.user_id}</div>
                                    <div style="font-size: 12px; color: var(--gray);">${new Date(alert.timestamp).toLocaleTimeString()}</div>
                                </div>
                                <div style="color: ${color};">${alert.severity}</div>
                            </div>
                        `;
                    }).join('');
                } else {
                    alertsList.innerHTML = '<div style="color: var(--gray); text-align: center; padding: 20px;">No recent alerts</div>';
                }
                
            } catch (error) {
                console.error('Error fetching dashboard data:', error);
            }
        }
        
        fetchDashboardData();
        setInterval(fetchDashboardData, 3000);
    </script>
</body>
</html>
    """


# ==================== MAIN ====================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚀 SecureHack AI - Shareable Multi-User Login System")
    print("="*80)
    print("\n✅ ML Models Loaded:", f"{ml_system.model.model_accuracy:.2%}")
    
    print("\n👥 Pre-configured Users (Share these with friends):")
    print("   • admin    (admin123) - Administrator 👑")
    print("   • alice    (alice123) - Developer 👩‍💻")
    print("   • bob      (bob123)   - Developer 👨‍💻")
    print("   • charlie  (charlie123) - Analyst 📊")
    print("   • david    (david123) - Manager 💼")
    print("   • eve      (eve123)   - Intern 🎓")
    
    print("\n🔗 SHAREABLE LINK (Send this to your friends):")
    print(f"{Colors.BOLD}{Colors.CYAN}   http://{os.environ.get('COMPUTERNAME', 'localhost')}:8000/share{Colors.END}")
    
    print("\n📱 Access URLs:")
    print("   • Share Page:  http://localhost:8000/share")
    print("   • Login:       http://localhost:8000")
    print("   • Dashboard:   http://localhost:8000/dashboard")
    
    print("\n" + "="*80)
    print("🚀 Starting server...")
    print("="*80 + "\n")
    
    uvicorn.run(
        "newcode:app",
        host="0.0.0.0",  # Listen on all interfaces so friends can connect
        port=8000,
        reload=True
    )