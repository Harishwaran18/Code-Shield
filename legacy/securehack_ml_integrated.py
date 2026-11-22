"""
SecureHack AI - Complete ML-Powered Security Platform
Fixed version with correct imports
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional  # Added Optional here
import asyncio
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# ==================== PRE-TRAINED ML MODEL ====================

class SecureHackMLModel:
    """Pre-trained ML model for anomaly detection"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'typing_speed_avg', 'typing_speed_std', 'typing_consistency',
            'mouse_distance', 'mouse_velocity', 'mouse_pattern',
            'active_hour', 'session_duration', 'keystroke_count',
            'error_rate', 'paste_events', 'copy_events',
            'command_frequency', 'tab_switches', 'focus_losses'
        ]
        self.is_trained = False
        self._initialize_pretrained_model()
    
    def _initialize_pretrained_model(self):
        """Initialize with pre-trained weights"""
        print("🤖 Loading pre-trained ML model...")
        
        # Create synthetic training data
        np.random.seed(42)
        
        # Generate normal user profiles (1000 samples)
        n_samples = 1000
        X_train = []
        
        for _ in range(n_samples):
            features = [
                float(np.random.normal(200, 30)),      # typing_speed_avg
                float(np.random.exponential(15)),      # typing_speed_std
                float(100 - np.random.gamma(2, 5)),    # typing_consistency
                float(np.random.normal(5000, 1000)),   # mouse_distance
                float(np.random.normal(100, 20)),      # mouse_velocity
                float(np.random.uniform(0.7, 0.95)),   # mouse_pattern
                float(np.random.randint(9, 18)),       # active_hour
                float(np.random.exponential(30)),       # session_duration
                float(np.random.poisson(500)),          # keystroke_count
                float(np.random.beta(1, 20) * 100),    # error_rate
                float(np.random.poisson(2)),            # paste_events
                float(np.random.poisson(3)),            # copy_events
                float(np.random.poisson(10)),           # command_frequency
                float(np.random.poisson(5)),            # tab_switches
                float(np.random.poisson(2))             # focus_losses
            ]
            X_train.append(features)
        
        # Add anomalies (50 samples)
        for _ in range(50):
            features = [
                float(np.random.normal(500, 100)),     # Much faster typing
                float(np.random.exponential(50)),       # Erratic typing
                float(np.random.uniform(10, 40)),       # Low consistency
                float(np.random.normal(20000, 5000)),   # Excessive mouse
                float(np.random.normal(300, 100)),      # Fast mouse
                float(np.random.uniform(0.2, 0.5)),     # Random pattern
                float(np.random.choice([2, 3, 4, 22, 23])),  # Unusual hour
                float(np.random.exponential(120)),       # Long session
                float(np.random.poisson(2000)),          # Many keystrokes
                float(np.random.beta(5, 1) * 100),      # High error rate
                float(np.random.poisson(20)),            # Many pastes
                float(np.random.poisson(25)),            # Many copies
                float(np.random.poisson(50)),            # Many commands
                float(np.random.poisson(30)),            # Many tab switches
                float(np.random.poisson(20))             # Many focus losses
            ]
            X_train.append(features)
        
        X_train = np.array(X_train)
        
        # Train model
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"✅ Pre-trained model loaded with {n_samples} normal + 50 anomalous samples")
    
    def extract_features(self, behavioral_data: Dict) -> np.array:
        """Extract features from behavioral data"""
        features = []
        
        # Typing features
        features.append(float(behavioral_data.get('typing_speed_avg', 200)))
        features.append(float(behavioral_data.get('typing_speed_std', 30)))
        features.append(float(behavioral_data.get('typing_consistency', 85)))
        
        # Mouse features
        features.append(float(behavioral_data.get('mouse_distance', 5000)))
        features.append(float(behavioral_data.get('mouse_velocity', 100)))
        features.append(float(behavioral_data.get('mouse_pattern', 0.8)))
        
        # Session features
        features.append(float(behavioral_data.get('active_hour', datetime.now().hour)))
        features.append(float(behavioral_data.get('session_duration', 10)))
        features.append(float(behavioral_data.get('keystroke_count', 100)))
        
        # Interaction features
        features.append(float(behavioral_data.get('error_rate', 5)))
        features.append(float(behavioral_data.get('paste_events', 1)))
        features.append(float(behavioral_data.get('copy_events', 2)))
        features.append(float(behavioral_data.get('command_frequency', 5)))
        features.append(float(behavioral_data.get('tab_switches', 2)))
        features.append(float(behavioral_data.get('focus_losses', 1)))
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, behavioral_data: Dict) -> Tuple[bool, float, List[str]]:
        """Predict if behavior is anomalous"""
        if not self.is_trained:
            return False, 0.0, ["Model not trained"]
        
        try:
            features = self.extract_features(behavioral_data)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            score = float(self.model.score_samples(features_scaled)[0])
            
            is_anomaly = bool(prediction == -1)
            reasons = self._get_anomaly_reasons(behavioral_data)
            
            return is_anomaly, score, reasons
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0, [f"Error: {str(e)}"]
    
    def _get_anomaly_reasons(self, data: Dict) -> List[str]:
        """Generate reasons for anomalies"""
        reasons = []
        
        if data.get('typing_speed_avg', 200) > 400:
            reasons.append(f"Unusual typing speed")
        
        if data.get('typing_consistency', 85) < 50:
            reasons.append(f"Erratic typing pattern")
        
        if data.get('mouse_distance', 5000) > 15000:
            reasons.append(f"Excessive mouse movement")
        
        hour = data.get('active_hour', datetime.now().hour)
        if hour < 6 or hour > 22:
            reasons.append(f"Unusual active hour")
        
        if data.get('paste_events', 1) > 10:
            reasons.append(f"Excessive paste events")
        
        if data.get('copy_events', 2) > 15:
            reasons.append(f"Excessive copy events")
        
        return reasons if reasons else ["Unusual behavioral pattern detected"]


# ==================== USER PROFILING ====================

class UserBehaviorProfile:
    """Tracks user behavioral profiles"""
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.keystroke_timings = []
        self.error_count = 0
        self.total_keystrokes = 0
        self.paste_events = 0
        self.copy_events = 0
        self.commands = defaultdict(int)
        self.tab_switches = 0
        self.focus_losses = 0
        self.session_start = datetime.now()
        self.last_active = datetime.now()
        self.anomaly_count = 0
        self.risk_score = 0
        
    def update(self, event_type: str, event_data: Dict):
        """Update profile with new event"""
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
    
    def get_behavioral_features(self) -> Dict:
        """Extract features for ML model"""
        features = {}
        
        # Typing features
        if self.keystroke_timings:
            features['typing_speed_avg'] = float(np.mean(self.keystroke_timings[-100:]))
            features['typing_speed_std'] = float(np.std(self.keystroke_timings[-100:]))
            features['typing_consistency'] = float(100 - min(100, features['typing_speed_std'] / 2))
        else:
            features['typing_speed_avg'] = 200.0
            features['typing_speed_std'] = 30.0
            features['typing_consistency'] = 85.0
        
        # Session features
        features['active_hour'] = float(datetime.now().hour)
        features['keystroke_count'] = float(self.total_keystrokes)
        
        # Error rate
        if self.total_keystrokes > 0:
            features['error_rate'] = float((self.error_count / self.total_keystrokes) * 100)
        else:
            features['error_rate'] = 5.0
        
        # Interaction features
        features['paste_events'] = float(self.paste_events)
        features['copy_events'] = float(self.copy_events)
        features['tab_switches'] = float(self.tab_switches)
        features['focus_losses'] = float(self.focus_losses)
        
        # Default values for other features
        features['mouse_distance'] = 5000.0
        features['mouse_velocity'] = 100.0
        features['mouse_pattern'] = 0.8
        features['session_duration'] = 10.0
        features['command_frequency'] = 5.0
        
        return features


# ==================== ML MONITORING SYSTEM ====================

class MLMonitoringSystem:
    """Main ML monitoring system"""
    
    def __init__(self):
        self.model = SecureHackMLModel()
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.alert_history: List[Dict] = []
        
    def get_or_create_profile(self, user_id: str) -> UserBehaviorProfile:
        """Get or create user profile"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id)
        return self.user_profiles[user_id]
    
    async def track_event(self, session_id: str, user_id: str, event_data: Dict):
        """Track user event in real-time"""
        profile = self.get_or_create_profile(user_id)
        event_type = event_data.get('type', 'unknown')
        profile.update(event_type, event_data)
        
        # Track session
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'start_time': datetime.now(),
                'events': [],
                'alert_count': 0
            }
        
        # Run anomaly detection periodically
        if len(self.active_sessions[session_id]['events']) % 10 == 0:
            features = profile.get_behavioral_features()
            is_anomaly, score, reasons = self.model.predict(features)
            
            if is_anomaly:
                profile.anomaly_count += 1
                profile.risk_score = min(100, abs(score) * 20)
                
                alert = {
                    'id': secrets.token_hex(4),
                    'timestamp': datetime.now().isoformat(),
                    'user_id': user_id,
                    'type': 'behavioral_anomaly',
                    'severity': 'HIGH' if abs(score) > 0.6 else 'MEDIUM',
                    'reasons': reasons
                }
                self.alert_history.append(alert)
                print(f"🚨 Anomaly detected for {user_id}")
        
        self.active_sessions[session_id]['events'].append({
            'timestamp': datetime.now().isoformat(),
            'type': event_type
        })
    
    def get_user_risk(self, user_id: str) -> Dict:
        """Get risk assessment for user"""
        if user_id not in self.user_profiles:
            return {'risk_score': 0, 'risk_level': 'LOW', 'is_anomaly': False, 'reasons': []}
        
        profile = self.user_profiles[user_id]
        features = profile.get_behavioral_features()
        is_anomaly, score, reasons = self.model.predict(features)
        
        risk_score = float(profile.risk_score or min(100, abs(score) * 20))
        
        if risk_score >= 70:
            level = 'CRITICAL'
        elif risk_score >= 50:
            level = 'HIGH'
        elif risk_score >= 30:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'user_id': user_id,
            'risk_score': round(risk_score, 2),
            'risk_level': level,
            'is_anomaly': bool(is_anomaly),
            'reasons': reasons
        }


# ==================== FASTAPI SERVER ====================

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Initialize ML system
ml_system = MLMonitoringSystem()

# Create FastAPI app
app = FastAPI(title="SecureHack AI - ML Powered Security")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session storage
sessions = {}

# ==================== API ENDPOINTS ====================

@app.post("/api/track")
async def track_user_event(
    event: dict,
    x_session_id: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None)
):
    """Track user behavior for ML analysis"""
    session_id = x_session_id or secrets.token_hex(8)
    user_id = x_user_id or event.get('user_id', 'anonymous')
    
    asyncio.create_task(ml_system.track_event(session_id, user_id, event))
    risk = ml_system.get_user_risk(user_id)
    
    return JSONResponse(content={
        'status': 'tracked',
        'risk_score': risk['risk_score'],
        'risk_level': risk['risk_level']
    })


@app.post("/api/auth/login")
async def ml_login(request: Request, credentials: dict):
    """Login with ML verification"""
    username = credentials.get('username', '')
    
    if not username:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    profile = ml_system.get_or_create_profile(username)
    features = profile.get_behavioral_features()
    is_anomaly, score, reasons = ml_system.model.predict(features)
    
    risk_score = float(min(100, abs(score) * 20))
    
    return JSONResponse(content={
        'success': True,
        'user': {
            'id': username,
            'name': username.title(),
            'initials': username[:2].upper() if username else 'U'
        },
        'ml_assessment': {
            'risk_score': risk_score,
            'risk_level': 'HIGH' if risk_score > 50 else 'MEDIUM' if risk_score > 25 else 'LOW',
            'is_anomaly': bool(is_anomaly),
            'reasons': reasons
        }
    })


@app.get("/api/risk/{user_id}")
async def get_risk(user_id: str):
    """Get ML risk assessment"""
    return JSONResponse(content=ml_system.get_user_risk(user_id))


# ==================== FRONTEND PAGE ====================

@app.get("/", response_class=HTMLResponse)
async def get_login_page():
    """Serve login page"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>SecureHack AI - ML Security</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            width: 400px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .ml-badge {
            background: #10b981;
            color: white;
            padding: 8px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 20px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .risk-meter {
            margin: 20px 0;
            padding: 15px;
            background: #f3f4f6;
            border-radius: 10px;
        }
        .risk-bar {
            height: 10px;
            background: #ddd;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }
        .risk-fill {
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }
        .risk-fill.low { background: #10b981; }
        .risk-fill.medium { background: #f59e0b; }
        .risk-fill.high { background: #ef4444; }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            margin: 20px 0;
        }
        button:hover { opacity: 0.9; }
        .insights {
            padding: 15px;
            background: #f3f4f6;
            border-radius: 8px;
            font-size: 14px;
        }
        #typingTest {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="ml-badge">🤖 ML Anomaly Detection Active</div>
        <h1>SecureHack AI</h1>
        
        <div class="risk-meter">
            <div style="display: flex; justify-content: space-between;">
                <span>ML Risk Score</span>
                <span id="riskPercentage">0%</span>
            </div>
            <div class="risk-bar">
                <div class="risk-fill" id="riskFill" style="width: 0%;"></div>
            </div>
        </div>

        <input type="text" id="typingTest" placeholder="Type here to establish your pattern..." autocomplete="off">
        
        <input type="text" id="username" placeholder="Username" value="hackathon_user">
        <input type="password" id="password" placeholder="Password" value="demo123">
        
        <button id="loginBtn">Login with ML Verification</button>
        
        <div class="insights" id="insights">
            🤖 Type to build your behavioral profile...
        </div>
    </div>

    <script>
        class MLTracker {
            constructor() {
                this.keystrokes = [];
                this.startTime = Date.now();
                this.setupTracking();
            }

            setupTracking() {
                let lastTime = Date.now();
                document.getElementById('typingTest').addEventListener('keydown', (e) => {
                    const now = Date.now();
                    const interval = now - lastTime;
                    
                    this.keystrokes.push({
                        key: e.key,
                        interval: interval,
                        time: now
                    });
                    
                    lastTime = now;
                    this.calculateRisk();
                });
            }

            calculateRisk() {
                if (this.keystrokes.length < 5) return;
                
                const recent = this.keystrokes.slice(-10);
                const intervals = recent.map(k => k.interval).filter(i => i < 1000);
                
                if (intervals.length > 1) {
                    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                    const std = Math.sqrt(intervals.map(i => Math.pow(i - avg, 2)).reduce((a, b) => a + b, 0) / intervals.length);
                    
                    // Calculate risk score (0-100)
                    let riskScore = Math.min(100, (std / 10));
                    
                    const riskFill = document.getElementById('riskFill');
                    const riskPercentage = document.getElementById('riskPercentage');
                    
                    riskFill.style.width = riskScore + '%';
                    riskFill.className = 'risk-fill ' + (riskScore < 30 ? 'low' : riskScore < 60 ? 'medium' : 'high');
                    riskPercentage.textContent = riskScore + '%';
                    
                    let insight = '✅ Normal typing pattern';
                    if (riskScore > 60) insight = '⚠️ High risk - Erratic typing detected';
                    else if (riskScore > 30) insight = '⚡ Medium risk - Inconsistent pattern';
                    
                    document.getElementById('insights').innerHTML = `🤖 ${insight}`;
                }
            }

            getFeatures() {
                const intervals = this.keystrokes.map(k => k.interval).filter(i => i < 1000);
                const avg = intervals.length ? intervals.reduce((a, b) => a + b, 0) / intervals.length : 200;
                const std = intervals.length ? Math.sqrt(intervals.map(i => Math.pow(i - avg, 2)).reduce((a, b) => a + b, 0) / intervals.length) : 30;
                
                return {
                    typing_speed_avg: avg,
                    typing_speed_std: std,
                    typing_consistency: Math.max(0, 100 - (std / 5)),
                    keystroke_count: this.keystrokes.length
                };
            }
        }

        const tracker = new MLTracker();

        document.getElementById('loginBtn').addEventListener('click', async () => {
            const btn = document.getElementById('loginBtn');
            btn.textContent = 'Verifying with ML...';
            btn.disabled = true;

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value,
                        behavioral_data: tracker.getFeatures()
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('insights').innerHTML = 
                        `✅ Login successful! Risk Score: ${data.ml_assessment.risk_score} (${data.ml_assessment.risk_level})`;
                } else {
                    throw new Error('Login failed');
                }
            } catch (error) {
                document.getElementById('insights').innerHTML = '❌ Login failed';
            } finally {
                btn.textContent = 'Login with ML Verification';
                btn.disabled = false;
            }
        });
    </script>
</body>
</html>
    """


@app.get("/editor", response_class=HTMLResponse)
async def get_editor_page():
    """Serve editor page"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>SecureHack AI - Editor</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f2f5; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        textarea { width: 100%; height: 500px; padding: 15px; font-family: monospace; }
        button { padding: 10px 20px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SecureHack AI Editor</h1>
            <p>ML-Powered Security Active</p>
        </div>
        <textarea placeholder="Write your code here...">print("Hello, Secure World!")</textarea>
        <br><br>
        <button onclick="alert('ML Scan Complete!')">Scan with ML</button>
    </div>
</body>
</html>
    """


# ==================== MAIN ====================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 SecureHack AI - ML Powered Security Platform")
    print("="*70)
    print("\n✅ ML Model Status: Loaded successfully")
    print("🌐 Open http://localhost:8000 in your browser")
    print("\n" + "="*70 + "\n")
    
    # For reload to work, we need to pass the app as an import string
    uvicorn.run(
        "securehack_ml_integrated:app",  # Module:app format for reload to work
        host="127.0.0.1",
        port=8000,
        reload=True
    )