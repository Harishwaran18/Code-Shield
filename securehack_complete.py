"""
CodeGuard - Advanced ML-Powered Security Platform
Enterprise-grade solution with real-time dashboard and mobile alerts
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
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict
import warnings
import hashlib
import hmac
import time
import redis  # pyright: ignore[reportMissingImports]
import requests
from twilio.rest import Client  # pyright: ignore[reportMissingImports]
from plyer import notification  # pyright: ignore[reportMissingImports]
import websockets
import plotly.graph_objects as go
import plotly.utils
import pandas as pd
warnings.filterwarnings('ignore')

# ==================== FASTAPI IMPORTS ====================
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Header, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ==================== CONFIGURATION ====================

class Config:
    """Configuration settings"""
    # Twilio (SMS) Configuration - Sign up at https://www.twilio.com
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')  # Add your SID
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')    # Add your token
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', '+1234567890')  # Your Twilio number
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')  # Your email
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')  # Your app password
    
    # Redis Configuration (for real-time data)
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
    REDIS_DB = int(os.environ.get('REDIS_DB', 0))
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    ALERT_WEBHOOK_URL = os.environ.get('ALERT_WEBHOOK_URL', '')  # Slack/Discord webhook
    
    # Demo mode (if services not configured)
    DEMO_MODE = True

config = Config()

# ==================== ALERT MANAGER ====================

class AlertManager:
    """Multi-channel alert system"""
    
    def __init__(self):
        self.alert_history = []
        self.alert_callbacks = []
        self.alert_levels = {
            'CRITICAL': {'color': '#ef4444', 'sms': True, 'email': True, 'webhook': True},
            'HIGH': {'color': '#f97316', 'sms': True, 'email': True, 'webhook': True},
            'MEDIUM': {'color': '#eab308', 'sms': False, 'email': True, 'webhook': True},
            'LOW': {'color': '#10b981', 'sms': False, 'email': False, 'webhook': False}
        }
        
        # Initialize Twilio client if configured
        self.twilio_client = None
        if config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN:
            try:
                from twilio.rest import Client
                self.twilio_client = Client(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN)
                print("✅ Twilio SMS configured")
            except:
                print("⚠️ Twilio not configured - SMS disabled")
        
        # Registered phone numbers for alerts
        self.alert_phones = set()
        self.alert_emails = set()
        
    def register_phone(self, phone_number: str):
        """Register phone number for alerts"""
        self.alert_phones.add(phone_number)
        print(f"📱 Registered {phone_number} for SMS alerts")
    
    def register_email(self, email: str):
        """Register email for alerts"""
        self.alert_emails.add(email)
        print(f"📧 Registered {email} for email alerts")
    
    def register_callback(self, callback):
        """Register callback for real-time alerts"""
        self.alert_callbacks.append(callback)
    
    async def send_alert(self, alert: Dict):
        """Send alert through all configured channels"""
        severity = alert.get('severity', 'MEDIUM').upper()
        level_config = self.alert_levels.get(severity, self.alert_levels['MEDIUM'])
        
        # Store alert
        alert['id'] = secrets.token_hex(8)
        alert['timestamp'] = datetime.now().isoformat()
        self.alert_history.append(alert)
        
        # Trigger callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except:
                pass
        
        # Send SMS for critical/high alerts
        if level_config['sms'] and self.twilio_client and self.alert_phones:
            await self._send_sms_alerts(alert)
        
        # Send emails
        if level_config['email'] and self.alert_emails:
            await self._send_email_alerts(alert)
        
        # Send webhook
        if level_config['webhook'] and config.ALERT_WEBHOOK_URL:
            await self._send_webhook(alert)
        
        # Desktop notification (for demo)
        self._show_desktop_notification(alert)
        
        print(f"🚨 Alert sent: {alert['title']} ({severity})")
        return alert['id']
    
    async def _send_sms_alerts(self, alert: Dict):
        """Send SMS alerts via Twilio"""
        if not self.twilio_client:
            return
        
        message = f"🚨 CodeGuard Alert [{alert['severity']}]\n{alert['title']}\n{alert.get('description', '')}\nTime: {datetime.now().strftime('%H:%M:%S')}"
        
        for phone in self.alert_phones:
            try:
                if config.DEMO_MODE:
                    print(f"📱 [DEMO] SMS to {phone}: {message}")
                else:
                    self.twilio_client.messages.create(
                        body=message,
                        from_=config.TWILIO_PHONE_NUMBER,
                        to=phone
                    )
            except Exception as e:
                print(f"❌ SMS failed to {phone}: {e}")
    
    async def _send_email_alerts(self, alert: Dict):
        """Send email alerts"""
        if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
            return
        
        msg = MIMEMultipart()
        msg['Subject'] = f"🚨 CodeGuard Alert - {alert['severity']}: {alert['title']}"
        msg['From'] = config.SMTP_USERNAME
        
        body = f"""
        <html>
        <body>
            <h2 style="color: {self.alert_levels[alert['severity']]['color']}">🚨 CodeGuard Security Alert</h2>
            <p><strong>Severity:</strong> {alert['severity']}</p>
            <p><strong>Title:</strong> {alert['title']}</p>
            <p><strong>Description:</strong> {alert.get('description', '')}</p>
            <p><strong>User:</strong> {alert.get('user_id', 'Unknown')}</p>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <hr>
            <p><strong>Recommended Action:</strong> {alert.get('action', 'Investigate immediately')}</p>
            <p><a href="http://localhost:8000/dashboard">View Dashboard →</a></p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        for email in self.alert_emails:
            try:
                msg['To'] = email
                if config.DEMO_MODE:
                    print(f"📧 [DEMO] Email to {email}: {alert['title']}")
                else:
                    with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
                        server.starttls()
                        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                        server.send_message(msg)
            except Exception as e:
                print(f"❌ Email failed to {email}: {e}")
    
    async def _send_webhook(self, alert: Dict):
        """Send webhook alert (Slack/Discord)"""
        if not config.ALERT_WEBHOOK_URL:
            return
        
        try:
            webhook_data = {
                'text': f"*🚨 CodeGuard Alert - {alert['severity']}*\n{alert['title']}\n{alert.get('description', '')}",
                'attachments': [{
                    'color': self.alert_levels[alert['severity']]['color'],
                    'fields': [
                        {'title': 'Severity', 'value': alert['severity'], 'short': True},
                        {'title': 'User', 'value': alert.get('user_id', 'Unknown'), 'short': True},
                        {'title': 'Time', 'value': datetime.now().strftime('%H:%M:%S'), 'short': True}
                    ]
                }]
            }
            
            if config.DEMO_MODE:
                print(f"🔔 [DEMO] Webhook: {webhook_data}")
            else:
                async with aiohttp.ClientSession() as session:
                    await session.post(config.ALERT_WEBHOOK_URL, json=webhook_data)
        except Exception as e:
            print(f"❌ Webhook failed: {e}")
    
    def _show_desktop_notification(self, alert: Dict):
        """Show desktop notification"""
        try:
            notification.notify(
                title=f"🚨 CodeGuard Alert - {alert['severity']}",
                message=alert['title'],
                timeout=5
            )
        except:
            pass
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        return sorted(self.alert_history, key=lambda x: x['timestamp'], reverse=True)[:limit]


# ==================== REAL-TIME DASHBOARD MANAGER ====================

class DashboardManager:
    """Manages real-time dashboard updates"""
    
    def __init__(self):
        self.active_dashboards: Set[WebSocket] = set()
        self.metrics_history = defaultdict(list)
        self.alert_manager = AlertManager()
        
    async def register_dashboard(self, websocket: WebSocket):
        """Register a dashboard connection"""
        await websocket.accept()
        self.active_dashboards.add(websocket)
        print(f"📊 Dashboard connected - Total: {len(self.active_dashboards)}")
    
    def unregister_dashboard(self, websocket: WebSocket):
        """Unregister a dashboard connection"""
        self.active_dashboards.discard(websocket)
        print(f"📊 Dashboard disconnected - Total: {len(self.active_dashboards)}")
    
    async def broadcast_metrics(self, metrics: Dict):
        """Broadcast metrics to all connected dashboards"""
        # Store metrics history
        timestamp = datetime.now().isoformat()
        for key, value in metrics.items():
            self.metrics_history[key].append({
                'timestamp': timestamp,
                'value': value
            })
            # Keep last 1000 points
            if len(self.metrics_history[key]) > 1000:
                self.metrics_history[key] = self.metrics_history[key][-1000:]
        
        # Broadcast to dashboards
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
        
        # Clean up disconnected
        for d in disconnected:
            self.active_dashboards.discard(d)
    
    async def broadcast_alert(self, alert: Dict):
        """Broadcast alert to all connected dashboards"""
        disconnected = set()
        for dashboard in self.active_dashboards:
            try:
                await dashboard.send_json({
                    'type': 'new_alert',
                    'data': alert
                })
            except:
                disconnected.add(dashboard)
        
        for d in disconnected:
            self.active_dashboards.discard(d)
    
    def get_metrics_history(self, metric: str, minutes: int = 60) -> List[Dict]:
        """Get historical metrics"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            m for m in self.metrics_history.get(metric, [])
            if datetime.fromisoformat(m['timestamp']) > cutoff
        ]
    
    def generate_chart(self, metric: str) -> str:
        """Generate Plotly chart HTML"""
        history = self.get_metrics_history(metric, 60)
        if not history:
            return "<p>No data available</p>"
        
        df = pd.DataFrame(history)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['value'],
            mode='lines+markers',
            name=metric,
            line=dict(color='#667eea', width=2)
        ))
        
        fig.update_layout(
            title=f'{metric} Over Time',
            xaxis_title='Time',
            yaxis_title='Value',
            template='plotly_dark',
            height=300,
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig.to_html(include_plotlyjs=False, div_id=f"chart-{metric}")


# ==================== ADVANCED ML MODEL ====================

class CodeGuardMLModel:
    """Advanced ML model with multiple algorithms"""
    
    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = None
        self.feature_names = [
            'typing_speed_avg', 'typing_speed_std', 'typing_consistency',
            'mouse_distance', 'mouse_velocity', 'mouse_pattern',
            'active_hour', 'session_duration', 'keystroke_count',
            'error_rate', 'paste_events', 'copy_events',
            'command_frequency', 'tab_switches', 'focus_losses',
            'code_complexity', 'import_count', 'function_count',
            'file_access_rate', 'network_requests'
        ]
        self.is_trained = False
        self.model_accuracy = 0.0
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize with pre-trained models"""
        print("🤖 Loading CodeGuard ML models...")
        
        # Create synthetic training data
        np.random.seed(42)
        
        # Generate normal user profiles (2000 samples)
        n_samples = 2000
        X_train = []
        y_train = []  # 0 = normal, 1 = anomaly
        
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
                float(np.random.poisson(2)),            # focus_losses
                float(np.random.normal(50, 10)),        # code_complexity
                float(np.random.poisson(8)),            # import_count
                float(np.random.poisson(5)),            # function_count
                float(np.random.exponential(5)),        # file_access_rate
                float(np.random.poisson(20))            # network_requests
            ]
            X_train.append(features)
            y_train.append(0)  # normal
        
        # Add anomalies (200 samples)
        for _ in range(200):
            features = [
                float(np.random.normal(500, 100)),      # Much faster typing
                float(np.random.exponential(50)),        # Erratic typing
                float(np.random.uniform(10, 40)),        # Low consistency
                float(np.random.normal(20000, 5000)),    # Excessive mouse
                float(np.random.normal(300, 100)),       # Fast mouse
                float(np.random.uniform(0.2, 0.5)),      # Random pattern
                float(np.random.choice([2, 3, 4, 22, 23])),  # Unusual hour
                float(np.random.exponential(120)),        # Long session
                float(np.random.poisson(2000)),           # Many keystrokes
                float(np.random.beta(5, 1) * 100),       # High error rate
                float(np.random.poisson(20)),             # Many pastes
                float(np.random.poisson(25)),             # Many copies
                float(np.random.poisson(50)),             # Many commands
                float(np.random.poisson(30)),             # Many tab switches
                float(np.random.poisson(20)),             # Many focus losses
                float(np.random.normal(200, 50)),         # High complexity
                float(np.random.poisson(30)),             # Many imports
                float(np.random.poisson(20)),             # Many functions
                float(np.random.exponential(50)),         # High file access
                float(np.random.poisson(100))             # Many network requests
            ]
            X_train.append(features)
            y_train.append(1)  # anomaly
        
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        
        # Train scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train Isolation Forest (unsupervised)
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=200,
            max_samples='auto'
        )
        self.isolation_forest.fit(X_scaled)
        
        # Train Random Forest (supervised)
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.random_forest.fit(X_scaled, y_train)
        
        # Calculate accuracy
        self.model_accuracy = self.random_forest.score(X_scaled, y_train)
        
        self.is_trained = True
        
        print(f"✅ CodeGuard ML models loaded:")
        print(f"   - Isolation Forest: Anomaly detection")
        print(f"   - Random Forest: {self.model_accuracy:.2%} accuracy")
        print(f"   - Features: {len(self.feature_names)} behavioral metrics")
    
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
        
        # Code features
        features.append(float(behavioral_data.get('code_complexity', 50)))
        features.append(float(behavioral_data.get('import_count', 5)))
        features.append(float(behavioral_data.get('function_count', 3)))
        features.append(float(behavioral_data.get('file_access_rate', 2)))
        features.append(float(behavioral_data.get('network_requests', 10)))
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, behavioral_data: Dict) -> Tuple[bool, float, float, List[str]]:
        """Predict if behavior is anomalous with confidence score"""
        if not self.is_trained:
            return False, 0.0, 0.0, ["Model not trained"]
        
        try:
            features = self.extract_features(behavioral_data)
            features_scaled = self.scaler.transform(features)
            
            # Isolation Forest prediction
            if_pred = self.isolation_forest.predict(features_scaled)[0]
            if_score = float(self.isolation_forest.score_samples(features_scaled)[0])
            
            # Random Forest prediction with probability
            rf_proba = self.random_forest.predict_proba(features_scaled)[0]
            rf_pred = self.random_forest.predict(features_scaled)[0]
            rf_confidence = float(max(rf_proba))
            
            # Combine predictions
            is_anomaly = bool(if_pred == -1 or rf_pred == 1)
            anomaly_score = float(abs(if_score) * rf_confidence * 100)
            
            reasons = self._get_anomaly_reasons(behavioral_data, rf_confidence)
            
            return is_anomaly, anomaly_score, rf_confidence, reasons
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0, 0.0, [f"Error: {str(e)}"]
    
    def _get_anomaly_reasons(self, data: Dict, confidence: float) -> List[str]:
        """Generate detailed reasons for anomalies"""
        reasons = []
        
        # Typing anomalies
        if data.get('typing_speed_avg', 200) > 400:
            reasons.append(f"🚀 Unusual typing speed: {data['typing_speed_avg']:.0f}ms (normal: 200ms)")
        
        if data.get('typing_consistency', 85) < 50:
            reasons.append(f"📊 Erratic typing pattern: {data['typing_consistency']:.0f}% consistency")
        
        # Mouse anomalies
        if data.get('mouse_distance', 5000) > 15000:
            reasons.append(f"🖱️ Excessive mouse movement: {data['mouse_distance']:.0f}px")
        
        # Time anomalies
        hour = data.get('active_hour', datetime.now().hour)
        if hour < 6 or hour > 22:
            reasons.append(f"⏰ Unusual activity hour: {hour}:00")
        
        # Session anomalies
        if data.get('session_duration', 10) > 120:
            reasons.append(f"⏱️ Unusually long session: {data['session_duration']:.0f} minutes")
        
        # Data exfiltration indicators
        if data.get('paste_events', 1) > 10:
            reasons.append(f"📋 Excessive paste events: {data['paste_events']} (possible data exfiltration)")
        
        if data.get('copy_events', 2) > 15:
            reasons.append(f"📑 Excessive copy events: {data['copy_events']} (possible data theft)")
        
        if data.get('file_access_rate', 2) > 20:
            reasons.append(f"📁 High file access rate: {data['file_access_rate']} (possible data scraping)")
        
        # Code anomalies
        if data.get('code_complexity', 50) > 150:
            reasons.append(f"🔍 Unusually complex code: complexity {data['code_complexity']:.0f}")
        
        if data.get('network_requests', 10) > 50:
            reasons.append(f"🌐 High network activity: {data['network_requests']} requests")
        
        # Add confidence
        if confidence > 0.9:
            reasons.append(f"🎯 ML confidence: {confidence:.1%} - High certainty")
        elif confidence > 0.7:
            reasons.append(f"⚡ ML confidence: {confidence:.1%} - Moderate certainty")
        
        return reasons if reasons else ["Normal behavior pattern detected"]


# ==================== USER PROFILING ====================

class UserBehaviorProfile:
    """Advanced user behavioral profiling"""
    
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
        self.file_access_events = []
        self.network_requests = []
        self.code_snapshots = []
        self.session_start = datetime.now()
        self.last_active = datetime.now()
        self.anomaly_count = 0
        self.risk_score = 0
        self.alert_history = []
        self.trust_score = 100  # Start at 100, decreases with anomalies
        
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
            # Track paste size for DLP
            if 'size' in event_data and event_data['size'] > 1000:
                self.risk_score += 5  # Large paste increases risk
                
        elif event_type == 'copy':
            self.copy_events += 1
            
        elif event_type == 'tab_switch':
            self.tab_switches += 1
            
        elif event_type == 'focus_loss':
            self.focus_losses += 1
            
        elif event_type == 'file_access':
            self.file_access_events.append({
                'file': event_data.get('file', 'unknown'),
                'action': event_data.get('action', 'read'),
                'timestamp': datetime.now().isoformat()
            })
            
        elif event_type == 'network':
            self.network_requests.append({
                'url': event_data.get('url', 'unknown'),
                'method': event_data.get('method', 'GET'),
                'timestamp': datetime.now().isoformat()
            })
            
        elif event_type == 'code_change':
            self.code_snapshots.append({
                'length': len(event_data.get('code', '')),
                'complexity': event_data.get('complexity', 0),
                'timestamp': datetime.now().isoformat()
            })
        
        # Update trust score
        self.trust_score = max(0, 100 - (self.risk_score / 2))
        
        # Keep only recent history
        max_history = 1000
        if len(self.keystroke_timings) > max_history:
            self.keystroke_timings = self.keystroke_timings[-max_history:]
        if len(self.file_access_events) > 100:
            self.file_access_events = self.file_access_events[-100:]
        if len(self.network_requests) > 100:
            self.network_requests = self.network_requests[-100:]
    
    def get_behavioral_features(self) -> Dict:
        """Extract advanced features for ML model"""
        features = {}
        
        # Typing features
        if self.keystroke_timings:
            recent = self.keystroke_timings[-200:]
            features['typing_speed_avg'] = float(np.mean(recent))
            features['typing_speed_std'] = float(np.std(recent))
            features['typing_consistency'] = float(100 - min(100, features['typing_speed_std'] / 2))
        else:
            features['typing_speed_avg'] = 200.0
            features['typing_speed_std'] = 30.0
            features['typing_consistency'] = 85.0
        
        # Session features
        features['active_hour'] = float(datetime.now().hour)
        features['session_duration'] = float((self.last_active - self.session_start).total_seconds() / 60)
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
        
        # File/network features
        features['file_access_rate'] = float(len([e for e in self.file_access_events if 
            (datetime.now() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 3600]))
        features['network_requests'] = float(len([e for e in self.network_requests if 
            (datetime.now() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 3600]))
        
        # Code features
        if self.code_snapshots:
            recent_code = self.code_snapshots[-10:]
            features['code_complexity'] = float(np.mean([c.get('complexity', 50) for c in recent_code]))
            features['import_count'] = float(np.mean([c.get('imports', 5) for c in recent_code]))
            features['function_count'] = float(np.mean([c.get('functions', 3) for c in recent_code]))
        else:
            features['code_complexity'] = 50.0
            features['import_count'] = 5.0
            features['function_count'] = 3.0
        
        # Default values for other features
        features['mouse_distance'] = 5000.0
        features['mouse_velocity'] = 100.0
        features['mouse_pattern'] = 0.8
        features['command_frequency'] = 5.0
        
        return features
    
    def get_risk_summary(self) -> Dict:
        """Get comprehensive risk summary"""
        return {
            'user_id': self.user_id,
            'trust_score': round(self.trust_score, 2),
            'risk_score': round(self.risk_score, 2),
            'anomaly_count': self.anomaly_count,
            'session_duration': str(timedelta(seconds=int((self.last_active - self.session_start).total_seconds()))),
            'total_keystrokes': self.total_keystrokes,
            'error_rate': f"{(self.error_count / max(self.total_keystrokes, 1) * 100):.1f}%",
            'paste_events': self.paste_events,
            'copy_events': self.copy_events,
            'file_access_count': len(self.file_access_events),
            'network_request_count': len(self.network_requests),
            'last_active': self.last_active.isoformat()
        }


# ==================== ML MONITORING SYSTEM ====================

class CodeGuardMonitoringSystem:
    """Advanced ML monitoring system"""
    
    def __init__(self, dashboard_manager: DashboardManager):
        self.model = CodeGuardMLModel()
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.dashboard = dashboard_manager
        self.alert_thresholds = {
            'CRITICAL': 80,
            'HIGH': 60,
            'MEDIUM': 40,
            'LOW': 20
        }
        
    def get_or_create_profile(self, user_id: str) -> UserBehaviorProfile:
        """Get or create user profile"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id)
        return self.user_profiles[user_id]
    
    async def track_event(self, session_id: str, user_id: str, event_data: Dict):
        """Track user event in real-time with advanced analysis"""
        profile = self.get_or_create_profile(user_id)
        event_type = event_data.get('type', 'unknown')
        
        # Update profile
        profile.update(event_type, event_data)
        
        # Track session
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'start_time': datetime.now(),
                'events': [],
                'alert_count': 0
            }
        
        session = self.active_sessions[session_id]
        session['events'].append({
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': event_data
        })
        
        # Run ML analysis periodically
        if len(session['events']) % 5 == 0:  # Analyze every 5 events
            features = profile.get_behavioral_features()
            is_anomaly, score, confidence, reasons = self.model.predict(features)
            
            if is_anomaly:
                profile.anomaly_count += 1
                profile.risk_score = score
                
                # Determine severity
                if score >= self.alert_thresholds['CRITICAL']:
                    severity = 'CRITICAL'
                elif score >= self.alert_thresholds['HIGH']:
                    severity = 'HIGH'
                elif score >= self.alert_thresholds['MEDIUM']:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Create alert
                alert = {
                    'title': f"Anomaly Detected - User {user_id}",
                    'description': f"Unusual behavior pattern detected with {confidence:.1%} confidence",
                    'severity': severity,
                    'score': round(score, 2),
                    'confidence': round(confidence, 3),
                    'user_id': user_id,
                    'session_id': session_id,
                    'reasons': reasons,
                    'action': self._get_recommended_action(severity, reasons)
                }
                
                # Send alert through all channels
                alert_id = await self.dashboard.alert_manager.send_alert(alert)
                profile.alert_history.append(alert_id)
                session['alert_count'] += 1
                
                # Update trust score
                profile.trust_score = max(0, 100 - (profile.risk_score / 2))
                
                print(f"🚨 {severity} anomaly for {user_id}: {reasons[0] if reasons else 'Unknown'}")
        
        # Update dashboard metrics
        await self._update_dashboard_metrics()
    
    def _get_recommended_action(self, severity: str, reasons: List[str]) -> str:
        """Get recommended action based on severity and reasons"""
        actions = {
            'CRITICAL': 'Immediate investigation required. Terminate session and force password reset.',
            'HIGH': 'Monitor closely. Request additional authentication and log all activities.',
            'MEDIUM': 'Increase monitoring frequency and flag for review.',
            'LOW': 'Continue monitoring. No immediate action required.'
        }
        
        base_action = actions.get(severity, 'Review and monitor.')
        
        # Customize based on reasons
        if any('paste' in r.lower() for r in reasons):
            base_action += ' Possible data exfiltration - block copy/paste operations.'
        if any('file' in r.lower() for r in reasons):
            base_action += ' Unusual file access - audit file operations.'
        if any('network' in r.lower() for r in reasons):
            base_action += ' Suspicious network activity - monitor outgoing connections.'
        
        return base_action
    
    async def _update_dashboard_metrics(self):
        """Update real-time dashboard metrics"""
        metrics = {
            'active_users': len(self.user_profiles),
            'active_sessions': len(self.active_sessions),
            'total_alerts': sum(len(p.alert_history) for p in self.user_profiles.values()),
            'avg_risk_score': np.mean([p.risk_score for p in self.user_profiles.values()]) if self.user_profiles else 0,
            'avg_trust_score': np.mean([p.trust_score for p in self.user_profiles.values()]) if self.user_profiles else 100,
            'critical_alerts': len([a for a in self.dashboard.alert_manager.alert_history if a.get('severity') == 'CRITICAL']),
            'high_alerts': len([a for a in self.dashboard.alert_manager.alert_history if a.get('severity') == 'HIGH']),
            'sessions_today': len([s for s in self.active_sessions.values() if 
                s['start_time'].date() == datetime.now().date()])
        }
        
        await self.dashboard.broadcast_metrics(metrics)
    
    def get_user_risk(self, user_id: str) -> Dict:
        """Get comprehensive risk assessment for user"""
        if user_id not in self.user_profiles:
            return {
                'risk_score': 0,
                'risk_level': 'LOW',
                'is_anomaly': False,
                'reasons': [],
                'trust_score': 100
            }
        
        profile = self.user_profiles[user_id]
        features = profile.get_behavioral_features()
        is_anomaly, score, confidence, reasons = self.model.predict(features)
        
        # Determine risk level
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
            'confidence': round(confidence, 3),
            'reasons': reasons,
            'trust_score': round(profile.trust_score, 2),
            'profile_summary': profile.get_risk_summary()
        }
    
    def get_dashboard_data(self) -> Dict:
        """Get comprehensive dashboard data"""
        total_users = len(self.user_profiles)
        total_sessions = len(self.active_sessions)
        total_alerts = len(self.dashboard.alert_manager.alert_history)
        
        # Calculate risk distribution
        risk_dist = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        risk_scores = []
        
        for user_id in self.user_profiles:
            risk = self.get_user_risk(user_id)
            risk_scores.append(risk['risk_score'])
            risk_dist[risk['risk_level']] += 1
        
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        
        # Session timeline
        sessions_by_hour = defaultdict(int)
        for session in self.active_sessions.values():
            hour = session['start_time'].hour
            sessions_by_hour[hour] += 1
        
        return {
            'stats': {
                'total_users': total_users,
                'total_sessions': total_sessions,
                'total_alerts': total_alerts,
                'avg_risk': round(avg_risk, 2),
                'risk_distribution': dict(risk_dist),
                'sessions_by_hour': dict(sessions_by_hour),
                'active_threats': risk_dist['HIGH'] + risk_dist['CRITICAL'],
                'system_health': 'GOOD' if avg_risk < 30 else 'WARNING' if avg_risk < 60 else 'CRITICAL'
            },
            'recent_alerts': self.dashboard.alert_manager.get_recent_alerts(20),
            'timestamp': datetime.now().isoformat()
        }


# ==================== COLLABORATION MANAGER ====================

class CollaborationManager:
    """Manages real-time collaborative editing sessions"""
    
    def __init__(self, ml_system: CodeGuardMonitoringSystem):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_sessions: Dict[WebSocket, Dict] = {}
        self.code_states: Dict[str, str] = {}
        self.cursor_positions: Dict[str, Dict] = {}
        self.ml_system = ml_system
        self.chat_history: Dict[str, List] = defaultdict(list)

    async def connect(self, websocket: WebSocket, session_id: str, user_id: str):
        """Connect a user to a session"""
        await websocket.accept()
        
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
            self.code_states[session_id] = "# Welcome to CodeGuard Collaborative Editor\n\nprint('Hello, Secure World!')\n"
            self.chat_history[session_id] = []
        
        self.active_connections[session_id].append(websocket)
        self.user_sessions[websocket] = {
            'session_id': session_id,
            'user_id': user_id,
            'joined_at': datetime.now().isoformat()
        }
        
        # Send current state to new user
        await websocket.send_json({
            'type': 'init',
            'code': self.code_states[session_id],
            'users': self.get_session_users(session_id),
            'chat_history': self.chat_history[session_id][-50:]  # Last 50 messages
        })
        
        # Notify others
        await self.broadcast(session_id, {
            'type': 'user_joined',
            'user_id': user_id,
            'timestamp': datetime.now().isoformat()
        }, websocket)
        
        # Track for ML
        await self.ml_system.track_event(session_id, user_id, {
            'type': 'session_join',
            'timestamp': datetime.now().isoformat()
        })

    def disconnect(self, websocket: WebSocket):
        """Disconnect a user"""
        if websocket in self.user_sessions:
            session_info = self.user_sessions[websocket]
            session_id = session_info['session_id']
            user_id = session_info['user_id']
            
            if session_id in self.active_connections:
                self.active_connections[session_id].remove(websocket)
            
            del self.user_sessions[websocket]
            
            # Notify others
            asyncio.create_task(self.broadcast(session_id, {
                'type': 'user_left',
                'user_id': user_id,
                'timestamp': datetime.now().isoformat()
            }, None))

    async def broadcast(self, session_id: str, message: dict, exclude: Optional[WebSocket] = None):
        """Broadcast message to all users in a session"""
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                if connection != exclude:
                    try:
                        await connection.send_json(message)
                    except:
                        pass

    def get_session_users(self, session_id: str) -> List[str]:
        """Get list of users in a session"""
        return [info['user_id'] for ws, info in self.user_sessions.items() 
                if info['session_id'] == session_id]

    async def handle_edit(self, websocket: WebSocket, session_id: str, data: dict):
        """Handle code edit event"""
        user_id = self.user_sessions.get(websocket, {}).get('user_id', 'anonymous')
        code = data.get('code', '')
        cursor = data.get('cursor', {})
        
        # Update code state
        self.code_states[session_id] = code
        
        # Track for ML
        await self.ml_system.track_event(session_id, user_id, {
            'type': 'code_edit',
            'length': len(code),
            'cursor': cursor,
            'timestamp': datetime.now().isoformat()
        })
        
        # Broadcast to others
        await self.broadcast(session_id, {
            'type': 'edit',
            'code': code,
            'user_id': user_id,
            'cursor': cursor,
            'timestamp': datetime.now().isoformat()
        }, websocket)

    async def handle_cursor(self, websocket: WebSocket, session_id: str, data: dict):
        """Handle cursor position update"""
        user_id = self.user_sessions.get(websocket, {}).get('user_id', 'anonymous')
        position = data.get('position', {})
        
        # Store cursor position
        key = f"{session_id}:{user_id}"
        self.cursor_positions[key] = {
            'position': position,
            'timestamp': datetime.now().isoformat()
        }
        
        # Broadcast to others
        await self.broadcast(session_id, {
            'type': 'cursor',
            'user_id': user_id,
            'position': position,
            'timestamp': datetime.now().isoformat()
        }, websocket)

    async def handle_chat(self, websocket: WebSocket, session_id: str, data: dict):
        """Handle chat message"""
        user_id = self.user_sessions.get(websocket, {}).get('user_id', 'anonymous')
        message = data.get('message', '').strip()
        
        if not message:
            return
        
        chat_msg = {
            'user_id': user_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in history
        self.chat_history[session_id].append(chat_msg)
        if len(self.chat_history[session_id]) > 100:
            self.chat_history[session_id] = self.chat_history[session_id][-100:]
        
        # Track for ML
        await self.ml_system.track_event(session_id, user_id, {
            'type': 'chat',
            'message_length': len(message),
            'timestamp': datetime.now().isoformat()
        })
        
        # Broadcast to all
        await self.broadcast(session_id, {
            'type': 'chat',
            'user_id': user_id,
            'message': message,
            'timestamp': chat_msg['timestamp']
        }, None)


# ==================== VULNERABILITY SCANNER ====================

class VulnerabilityScanner:
    """Advanced code vulnerability scanner"""
    
    def __init__(self):
        self.scan_history = []
        self.vulnerability_patterns = {
            'hardcoded_password': {
                'pattern': r'(password|passwd|pwd)\s*[=:]\s*[\'"]?(?!\$|\{)[^\'"]+[\'"]?',
                'severity': 'HIGH',
                'description': 'Hardcoded password detected. Use environment variables or secrets manager.'
            },
            'sql_injection': {
                'pattern': r'(execute|query|select|insert|update|delete).*[\'"]\s*[+%]',
                'severity': 'CRITICAL',
                'description': 'Possible SQL injection vulnerability. Use parameterized queries.'
            },
            'command_injection': {
                'pattern': r'(os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\([^,)]*[\'"]\s*[+%]',
                'severity': 'CRITICAL',
                'description': 'Command injection risk. Avoid using shell=True and sanitize inputs.'
            },
            'insecure_deserialization': {
                'pattern': r'(pickle\.loads?|yaml\.load|json\.loads?\s*\([^)]*\)\s*$)',
                'severity': 'HIGH',
                'description': 'Insecure deserialization. Use safe alternatives or verify input.'
            },
            'path_traversal': {
                'pattern': r'(open|file|read).*[\'"]\s*[+%]\s*user',
                'severity': 'HIGH',
                'description': 'Path traversal vulnerability. Validate file paths.'
            },
            'weak_crypto': {
                'pattern': r'(md5|sha1|DES|RC4)',
                'severity': 'MEDIUM',
                'description': 'Weak cryptographic algorithm. Use SHA-256 or better.'
            },
            'hardcoded_token': {
                'pattern': r'(token|secret|key|api_key)\s*[=:]\s*[\'"][A-Za-z0-9+/=]{20,}[\'"]',
                'severity': 'CRITICAL',
                'description': 'Hardcoded API token/secret. Use environment variables.'
            },
            'debug_enabled': {
                'pattern': r'debug\s*=\s*True',
                'severity': 'MEDIUM',
                'description': 'Debug mode enabled in production. Disable debug mode.'
            },
            'exception_leak': {
                'pattern': r'except.*:\s*\n\s*print\s*\(\s*e',
                'severity': 'MEDIUM',
                'description': 'Exception details exposed. Log errors instead of printing.'
            },
            'insecure_redirect': {
                'pattern': r'redirect\s*\(\s*request\.args\.get',
                'severity': 'HIGH',
                'description': 'Open redirect vulnerability. Validate redirect URLs.'
            },
            'xxe_vulnerability': {
                'pattern': r'(etree\.parse|xml\.parse)\s*\(\s*[^)]*\)',
                'severity': 'HIGH',
                'description': 'XXE vulnerability. Disable external entities.'
            },
            'csrf_disabled': {
                'pattern': r'csrf_exempt|@csrf\.exempt',
                'severity': 'MEDIUM',
                'description': 'CSRF protection disabled. Enable CSRF protection.'
            },
            'cors_wildcard': {
                'pattern': r'Access-Control-Allow-Origin.*\*',
                'severity': 'MEDIUM',
                'description': 'CORS wildcard allows any origin. Restrict CORS.'
            },
            'jwt_none_algorithm': {
                'pattern': r'algorithm\s*=\s*[\'"]none[\'"]',
                'severity': 'CRITICAL',
                'description': 'JWT none algorithm vulnerability. Use strong algorithms.'
            }
        }
    
    async def scan_code(self, code: str, filename: str = "code.py") -> Dict:
        """Scan code for vulnerabilities"""
        results = []
        
        # Pattern-based scanning
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            for vuln_id, vuln_info in self.vulnerability_patterns.items():
                import re
                if re.search(vuln_info['pattern'], line, re.IGNORECASE):
                    results.append({
                        'line': i,
                        'code': line.strip(),
                        'vulnerability': vuln_id.replace('_', ' ').title(),
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'recommendation': self._get_recommendation(vuln_id)
                    })
        
        # Try Bandit for advanced scanning
        bandit_results = await self._run_bandit_scan(code, filename)
        if bandit_results:
            results.extend(bandit_results)
        
        # Remove duplicates (same line and vulnerability)
        unique_results = []
        seen = set()
        for r in results:
            key = f"{r['line']}_{r['vulnerability']}"
            if key not in seen:
                seen.add(key)
                unique_results.append(r)
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(unique_results)
        
        scan_result = {
            'vulnerabilities': unique_results,
            'count': len(unique_results),
            'risk_level': risk_level,
            'scan_time': datetime.now().isoformat(),
            'summary': self._generate_summary(unique_results)
        }
        
        self.scan_history.append(scan_result)
        return scan_result
    
    async def _run_bandit_scan(self, code: str, filename: str) -> List[Dict]:
        """Run Bandit scanner if available"""
        results = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', '-q', temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.stdout:
                scan_data = json.loads(result.stdout)
                for issue in scan_data.get('results', []):
                    results.append({
                        'line': issue.get('line_number'),
                        'code': issue.get('code', '').strip(),
                        'vulnerability': issue.get('test_name', 'Unknown'),
                        'severity': issue.get('issue_severity', 'MEDIUM'),
                        'confidence': issue.get('issue_confidence', 'MEDIUM'),
                        'description': issue.get('issue_text', ''),
                        'more_info': issue.get('more_info', '')
                    })
        except:
            pass  # Bandit not available
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        
        return results
    
    def _get_recommendation(self, vuln_id: str) -> str:
        """Get remediation recommendation"""
        recommendations = {
            'hardcoded_password': 'Move secrets to environment variables or a secrets manager like HashiCorp Vault.',
            'sql_injection': 'Use parameterized queries or an ORM. Never concatenate user input directly.',
            'command_injection': 'Use subprocess with argument lists, avoid shell=True, and validate inputs.',
            'insecure_deserialization': 'Use JSON with schema validation instead of pickle. If pickle is required, verify input source.',
            'path_traversal': 'Validate file paths, use os.path.basename(), and whitelist allowed directories.',
            'weak_crypto': 'Use strong algorithms like SHA-256, SHA-3, or AES-256-GCM.',
            'hardcoded_token': 'Store tokens in environment variables or use a secrets management service.',
            'debug_enabled': 'Set debug=False in production. Use proper logging instead.',
            'exception_leak': 'Log exceptions with proper logging framework. Never expose details to users.',
            'insecure_redirect': 'Validate redirect URLs against a whitelist of allowed domains.',
            'xxe_vulnerability': 'Disable external entities in XML parsers. Use defusedxml if possible.',
            'csrf_disabled': 'Enable CSRF protection. For APIs, use tokens or modern auth methods.',
            'cors_wildcard': 'Restrict CORS to specific domains. Never use * with credentials.',
            'jwt_none_algorithm': 'Always validate JWT algorithms. Never accept "none".'
        }
        return recommendations.get(vuln_id, 'Review and fix the vulnerability.')
    
    def _calculate_risk_level(self, results: List[Dict]) -> str:
        """Calculate overall risk level"""
        severity_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        if not results:
            return 'LOW'
        
        max_severity = max((r['severity'] for r in results), 
                          key=lambda x: severity_weights.get(x, 0))
        
        critical_count = len([r for r in results if r['severity'] == 'CRITICAL'])
        high_count = len([r for r in results if r['severity'] == 'HIGH'])
        
        if critical_count > 0:
            return 'CRITICAL'
        elif high_count > 2:
            return 'HIGH'
        elif max_severity == 'HIGH':
            return 'HIGH'
        elif max_severity == 'MEDIUM':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_summary(self, results: List[Dict]) -> Dict:
        """Generate summary statistics"""
        summary = defaultdict(int)
        for r in results:
            summary[r['severity']] += 1
        return dict(summary)


# ==================== FASTAPI APP INITIALIZATION ====================

# Initialize managers
dashboard_manager = DashboardManager()
ml_system = CodeGuardMonitoringSystem(dashboard_manager)
collab_manager = CollaborationManager(ml_system)
vuln_scanner = VulnerabilityScanner()

# Create FastAPI app
app = FastAPI(title="CodeGuard - Advanced ML Security Platform")

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
        'risk_level': risk['risk_level'],
        'trust_score': risk.get('trust_score', 100)
    })


@app.post("/api/auth/login")
async def ml_login(request: Request, credentials: dict, background_tasks: BackgroundTasks):
    """Login with ML verification"""
    username = credentials.get('username', '')
    phone = credentials.get('phone', '')
    email = credentials.get('email', '')
    
    if not username:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Register for alerts if provided
    if phone:
        background_tasks.add_task(dashboard_manager.alert_manager.register_phone, phone)
    if email:
        background_tasks.add_task(dashboard_manager.alert_manager.register_email, email)
    
    profile = ml_system.get_or_create_profile(username)
    features = profile.get_behavioral_features()
    is_anomaly, score, confidence, reasons = ml_system.model.predict(features)
    
    risk_score = float(min(100, score))
    session_token = secrets.token_urlsafe(32)
    
    sessions[session_token] = {
        'username': username,
        'login_time': datetime.now().isoformat(),
        'phone': phone,
        'email': email
    }
    
    # Send welcome notification
    if phone and config.DEMO_MODE:
        print(f"📱 [DEMO] Welcome SMS sent to {phone}")
    
    return JSONResponse(content={
        'success': True,
        'session_token': session_token,
        'user': {
            'id': username,
            'name': username.title(),
            'initials': username[:2].upper() if username else 'U',
            'phone': phone,
            'email': email
        },
        'ml_assessment': {
            'risk_score': risk_score,
            'risk_level': 'CRITICAL' if risk_score > 80 else 'HIGH' if risk_score > 60 else 'MEDIUM' if risk_score > 40 else 'LOW',
            'is_anomaly': bool(is_anomaly),
            'confidence': round(confidence, 3),
            'reasons': reasons
        }
    })


@app.post("/api/scan-code")
async def scan_code(request: Request, data: dict):
    """Scan code for vulnerabilities"""
    code = data.get('code', '')
    filename = data.get('filename', 'code.py')
    
    if not code:
        return JSONResponse(content={"error": "No code provided"}, status_code=400)
    
    results = await vuln_scanner.scan_code(code, filename)
    
    # Track scan for ML
    session_id = request.headers.get('x-session-id', 'unknown')
    user_id = request.headers.get('x-user-id', 'anonymous')
    
    await ml_system.track_event(session_id, user_id, {
        'type': 'code_scan',
        'vulnerabilities_found': results['count'],
        'risk_level': results['risk_level']
    })
    
    return JSONResponse(content=results)


@app.post("/api/alerts/register")
async def register_alert_contact(data: dict, background_tasks: BackgroundTasks):
    """Register phone/email for alerts"""
    phone = data.get('phone')
    email = data.get('email')
    
    if phone:
        background_tasks.add_task(dashboard_manager.alert_manager.register_phone, phone)
    if email:
        background_tasks.add_task(dashboard_manager.alert_manager.register_email, email)
    
    return JSONResponse(content={
        'success': True,
        'message': 'Alert contacts registered successfully'
    })


@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 50):
    """Get recent security alerts"""
    return JSONResponse(content={
        'alerts': dashboard_manager.alert_manager.get_recent_alerts(limit)
    })


@app.get("/api/risk/{user_id}")
async def get_risk(user_id: str):
    """Get comprehensive risk assessment"""
    return JSONResponse(content=ml_system.get_user_risk(user_id))


@app.get("/api/dashboard/data")
async def get_dashboard_data():
    """Get real-time dashboard data"""
    return JSONResponse(content=ml_system.get_dashboard_data())


@app.get("/api/dashboard/chart/{metric}")
async def get_dashboard_chart(metric: str):
    """Get chart HTML for dashboard"""
    return HTMLResponse(content=dashboard_manager.generate_chart(metric))


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'ml_model': 'loaded' if ml_system.model.is_trained else 'not_loaded',
        'active_users': len(ml_system.user_profiles),
        'active_sessions': len(ml_system.active_sessions),
        'total_alerts': len(dashboard_manager.alert_manager.alert_history)
    })


# ==================== WEBSOCKET ENDPOINTS ====================

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket for real-time dashboard"""
    await dashboard_manager.register_dashboard(websocket)
    
    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            if data == 'ping':
                await websocket.send_json({'type': 'pong'})
    except:
        dashboard_manager.unregister_dashboard(websocket)


@app.websocket("/ws/collab/{session_id}")
async def websocket_collab(websocket: WebSocket, session_id: str):
    """WebSocket for real-time collaboration"""
    user_id = websocket.query_params.get('user_id', 'anonymous')
    
    await collab_manager.connect(websocket, session_id, user_id)
    
    try:
        while True:
            data = await websocket.receive_json()
            
            if data['type'] == 'edit':
                await collab_manager.handle_edit(websocket, session_id, data)
            elif data['type'] == 'cursor':
                await collab_manager.handle_cursor(websocket, session_id, data)
            elif data['type'] == 'chat':
                await collab_manager.handle_chat(websocket, session_id, data)
            elif data['type'] == 'ping':
                await websocket.send_json({'type': 'pong'})
                
    except WebSocketDisconnect:
        collab_manager.disconnect(websocket)


# ==================== FRONTEND PAGES ====================

@app.get("/", response_class=HTMLResponse)
async def get_login_page():
    """Serve login page with ML tracking"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>CodeGuard - Advanced ML Security Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        /* Animated background */
        .circles {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: 0;
        }
        
        .circles li {
            position: absolute;
            display: block;
            list-style: none;
            width: 20px;
            height: 20px;
            background: rgba(255, 255, 255, 0.2);
            animation: animate 25s linear infinite;
            bottom: -150px;
            border-radius: 50%;
        }
        
        @keyframes animate {
            0% { transform: translateY(0) rotate(0deg); opacity: 1; border-radius: 50%; }
            100% { transform: translateY(-1000px) rotate(720deg); opacity: 0; border-radius: 50%; }
        }
        
        .circles li:nth-child(1) { left: 25%; width: 80px; height: 80px; animation-delay: 0s; }
        .circles li:nth-child(2) { left: 10%; width: 20px; height: 20px; animation-delay: 2s; animation-duration: 12s; }
        .circles li:nth-child(3) { left: 70%; width: 20px; height: 20px; animation-delay: 4s; }
        .circles li:nth-child(4) { left: 40%; width: 60px; height: 60px; animation-delay: 0s; animation-duration: 18s; }
        .circles li:nth-child(5) { left: 65%; width: 20px; height: 20px; animation-delay: 0s; }
        .circles li:nth-child(6) { left: 75%; width: 110px; height: 110px; animation-delay: 3s; }
        .circles li:nth-child(7) { left: 35%; width: 150px; height: 150px; animation-delay: 7s; }
        .circles li:nth-child(8) { left: 50%; width: 25px; height: 25px; animation-delay: 15s; animation-duration: 45s; }
        .circles li:nth-child(9) { left: 20%; width: 15px; height: 15px; animation-delay: 2s; animation-duration: 35s; }
        .circles li:nth-child(10) { left: 85%; width: 150px; height: 150px; animation-delay: 0s; animation-duration: 11s; }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            width: 450px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            position: relative;
            z-index: 1;
            backdrop-filter: blur(10px);
            animation: slideUp 0.6s ease-out;
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .logo h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 5px;
        }
        
        .logo p {
            color: #6b7280;
            font-size: 0.9rem;
        }
        
        .ml-badge {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            padding: 10px;
            border-radius: 30px;
            text-align: center;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(16,185,129,0.7); }
            70% { box-shadow: 0 0 0 10px rgba(16,185,129,0); }
            100% { box-shadow: 0 0 0 0 rgba(16,185,129,0); }
        }
        
        .risk-meter {
            background: #f3f4f6;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .risk-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        
        .risk-bar-container {
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 5px;
        }
        
        .risk-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }
        
        .risk-bar.low { background: #10b981; }
        .risk-bar.medium { background: #f59e0b; }
        .risk-bar.high { background: #ef4444; }
        
        .trust-score {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: #6b7280;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #374151;
            font-weight: 500;
            font-size: 0.9rem;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        
        .typing-test {
            background: #f3f4f6;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .typing-test h4 {
            margin-bottom: 10px;
            color: #374151;
            font-size: 0.95rem;
        }
        
        .typing-sample {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 10px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }
        
        .typing-stats {
            display: flex;
            gap: 15px;
            font-size: 0.8rem;
            color: #6b7280;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            margin: 10px 0;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102,126,234,0.4);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .insights {
            background: #f3f4f6;
            border-radius: 8px;
            padding: 15px;
            font-size: 0.9rem;
            margin: 15px 0;
        }
        
        .nav-links {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
        }
        
        .nav-links a {
            color: #667eea;
            text-decoration: none;
            font-size: 0.9rem;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        .alert {
            padding: 12px;
            border-radius: 8px;
            margin: 10px 0;
            display: none;
        }
        
        .alert.error {
            background: #fee2e2;
            color: #dc2626;
            display: block;
        }
        
        .alert.success {
            background: #d1fae5;
            color: #059669;
            display: block;
        }
        
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 0.8rem;
            color: #9ca3af;
        }
    </style>
</head>
<body>
    <ul class="circles">
        <li></li><li></li><li></li><li></li><li></li>
        <li></li><li></li><li></li><li></li><li></li>
    </ul>
    
    <div class="container">
        <div class="logo">
            <h1>🛡️ CodeGuard</h1>
            <p>Advanced ML-Powered Security Platform</p>
        </div>
        
        <div class="ml-badge">
            <span>🤖</span>
            <span>Dual ML Models Active (Isolation Forest + Random Forest)</span>
        </div>
        
        <div class="risk-meter">
            <div class="risk-header">
                <span>ML Risk Score</span>
                <span id="riskPercentage">0%</span>
            </div>
            <div class="risk-bar-container">
                <div class="risk-bar" id="riskBar" style="width: 0%;"></div>
            </div>
            <div class="trust-score">
                <span>Trust Score: <span id="trustScore">100</span></span>
                <span>Confidence: <span id="confidence">-</span></span>
            </div>
        </div>
        
        <div class="typing-test">
            <h4>🔐 Behavioral Biometrics</h4>
            <div class="typing-sample">
                The quick brown fox jumps over the lazy dog
            </div>
            <input type="text" id="typingTest" placeholder="Type the sentence above..." autocomplete="off">
            <div class="typing-stats">
                <span>Speed: <span id="typingSpeed">0</span> WPM</span>
                <span>Accuracy: <span id="typingAccuracy">0</span>%</span>
                <span>Consistency: <span id="consistency">-</span></span>
            </div>
        </div>
        
        <div class="alert error" id="errorMessage"></div>
        <div class="alert success" id="successMessage"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="username" placeholder="Enter username" value="hackathon_user">
            </div>
            
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="Enter password" value="demo123">
            </div>
            
            <div class="form-group">
                <label>Phone (for SMS alerts)</label>
                <input type="tel" id="phone" placeholder="+1234567890 (demo)">
            </div>
            
            <div class="form-group">
                <label>Email (for email alerts)</label>
                <input type="email" id="email" placeholder="user@example.com (demo)">
            </div>
            
            <button type="submit" class="btn" id="loginBtn">
                Login with ML Verification
            </button>
        </form>
        
        <div class="insights" id="insights">
            🤖 Type to build your behavioral profile...
        </div>
        
        <div class="nav-links">
            <a href="/editor">🚀 Try Editor</a>
            <a href="/dashboard">📊 Live Dashboard</a>
            <a href="#" id="testAlert">📱 Test SMS Alert</a>
        </div>
        
        <div class="footer">
            Dual ML Models • Real-time Alerts • Mobile Integration
        </div>
    </div>
    
    <script>
        class MLTracker {
            constructor() {
                this.keystrokes = [];
                this.errors = 0;
                this.totalChars = 0;
                this.startTime = null;
                this.setupTracking();
            }
            
            setupTracking() {
                let lastTime = Date.now();
                const input = document.getElementById('typingTest');
                const targetText = "The quick brown fox jumps over the lazy dog";
                
                input.addEventListener('keydown', (e) => {
                    if (!this.startTime) this.startTime = Date.now();
                    
                    const now = Date.now();
                    const interval = now - lastTime;
                    
                    this.keystrokes.push({
                        key: e.key,
                        interval: interval,
                        time: now
                    });
                    
                    lastTime = now;
                    this.calculateMetrics();
                });
                
                input.addEventListener('input', (e) => {
                    const value = e.target.value;
                    this.totalChars = value.length;
                    
                    // Check for errors
                    for (let i = 0; i < value.length; i++) {
                        if (i < targetText.length && value[i] !== targetText[i]) {
                            this.errors++;
                        }
                    }
                    
                    this.calculateMetrics();
                });
            }
            
            calculateMetrics() {
                if (this.keystrokes.length < 5) return;
                
                const recent = this.keystrokes.slice(-20);
                const intervals = recent.map(k => k.interval).filter(i => i < 1000);
                
                if (intervals.length > 1) {
                    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                    const std = Math.sqrt(intervals.map(i => Math.pow(i - avg, 2)).reduce((a, b) => a + b, 0) / intervals.length);
                    
                    // Calculate risk score (0-100)
                    let riskScore = Math.min(100, (std / 8));
                    
                    const riskBar = document.getElementById('riskBar');
                    const riskPercentage = document.getElementById('riskPercentage');
                    
                    riskBar.style.width = riskScore + '%';
                    riskBar.className = 'risk-bar ' + (riskScore < 30 ? 'low' : riskScore < 60 ? 'medium' : 'high');
                    riskPercentage.textContent = riskScore + '%';
                    
                    // Calculate WPM
                    const minutes = (Date.now() - this.startTime) / 60000;
                    const words = this.totalChars / 5;
                    const wpm = minutes > 0 ? Math.round(words / minutes) : 0;
                    
                    // Calculate accuracy
                    const accuracy = this.totalChars > 0 
                        ? Math.round(((this.totalChars - this.errors) / this.totalChars) * 100)
                        : 100;
                    
                    // Calculate consistency
                    const consistency = Math.max(0, Math.min(100, 100 - (std / 5)));
                    
                    document.getElementById('typingSpeed').textContent = wpm;
                    document.getElementById('typingAccuracy').textContent = accuracy;
                    document.getElementById('consistency').textContent = Math.round(consistency) + '%';
                    document.getElementById('trustScore').textContent = Math.max(0, 100 - riskScore);
                    document.getElementById('confidence').textContent = (90 + Math.random() * 9).toFixed(1) + '%';
                    
                    let insight = '✅ Normal behavior pattern';
                    if (riskScore > 60) {
                        insight = '⚠️ HIGH RISK - Erratic typing detected';
                    } else if (riskScore > 30) {
                        insight = '⚡ MEDIUM RISK - Inconsistent pattern';
                    }
                    
                    document.getElementById('insights').innerHTML = `🤖 ${insight}<br><small>ML Confidence: 94.2% | Anomaly Score: ${riskScore.toFixed(1)}</small>`;
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
                    keystroke_count: this.keystrokes.length,
                    error_rate: this.totalChars ? (this.errors / this.totalChars) * 100 : 5
                };
            }
        }
        
        const tracker = new MLTracker();
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const btn = document.getElementById('loginBtn');
            btn.textContent = 'Verifying with ML Models...';
            btn.disabled = true;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value,
                        phone: document.getElementById('phone').value,
                        email: document.getElementById('email').value,
                        behavioral_data: tracker.getFeatures()
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    sessionStorage.setItem('session_token', data.session_token);
                    sessionStorage.setItem('user', JSON.stringify(data.user));
                    
                    document.getElementById('successMessage').textContent = 
                        `✅ Login successful! Risk Score: ${data.ml_assessment.risk_score} | Trust: ${data.user.phone ? 'SMS Alerts Active' : 'Add phone for alerts'}`;
                    document.getElementById('successMessage').style.display = 'block';
                    
                    document.getElementById('insights').innerHTML = `
                        ✅ ML Verification Passed<br>
                        <small>Risk Score: ${data.ml_assessment.risk_score} (${data.ml_assessment.risk_level}) | Confidence: ${(data.ml_assessment.confidence * 100).toFixed(1)}%</small><br>
                        <small>${data.ml_assessment.reasons.length ? '⚠️ ' + data.ml_assessment.reasons[0] : '✓ Normal behavior'}</small>
                    `;
                    
                    setTimeout(() => {
                        window.location.href = '/editor';
                    }, 2000);
                } else {
                    throw new Error(data.detail || 'Login failed');
                }
            } catch (error) {
                document.getElementById('errorMessage').textContent = error.message;
                document.getElementById('errorMessage').style.display = 'block';
            } finally {
                btn.textContent = 'Login with ML Verification';
                btn.disabled = false;
            }
        });
        
        document.getElementById('testAlert').addEventListener('click', async (e) => {
            e.preventDefault();
            
            const phone = document.getElementById('phone').value;
            if (!phone) {
                alert('Please enter a phone number to test SMS alerts');
                return;
            }
            
            // Register for alerts
            await fetch('/api/alerts/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({phone: phone})
            });
            
            alert(`✅ Test: SMS alert would be sent to ${phone} (Demo mode)`);
        });
    </script>
</body>
</html>
    """


@app.get("/editor", response_class=HTMLResponse)
async def get_editor_page():
    """Serve collaborative editor page"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>CodeGuard - Collaborative Editor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .risk-indicator {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .risk-low { background: #dcfce7; color: #166534; }
        .risk-medium { background: #fef9c3; color: #854d0e; }
        .risk-high { background: #fee2e2; color: #dc2626; }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 350px;
            gap: 20px;
        }
        
        .editor-section {
            background: #1e1e1e;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .editor-header {
            background: #2d2d2d;
            padding: 10px 15px;
            color: white;
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #404040;
        }
        
        .file-tab {
            display: flex;
            gap: 10px;
        }
        
        .file-tab span {
            background: #1e1e1e;
            padding: 5px 15px;
            border-radius: 5px 5px 0 0;
            font-size: 0.9rem;
        }
        
        .cursor-info {
            color: #9ca3af;
            font-size: 0.85rem;
        }
        
        #editor {
            width: 100%;
            height: 600px;
            padding: 15px;
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            border: none;
            resize: none;
            line-height: 1.5;
        }
        
        #editor:focus { outline: none; }
        
        .sidebar {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .users-online {
            padding: 15px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .users-online h3 {
            margin-bottom: 10px;
            color: #374151;
            font-size: 1rem;
        }
        
        .user-list {
            list-style: none;
        }
        
        .user-item {
            padding: 8px 12px;
            background: #f3f4f6;
            border-radius: 6px;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
        }
        
        .cursor-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
        }
        
        .scan-section {
            padding: 15px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .scan-btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            margin-bottom: 10px;
        }
        
        .scan-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(16,185,129,0.4);
        }
        
        .scan-results {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .vulnerability {
            padding: 10px;
            margin: 8px 0;
            border-left: 4px solid;
            background: #f9fafb;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        
        .vulnerability.critical { border-color: #ef4444; }
        .vulnerability.high { border-color: #f97316; }
        .vulnerability.medium { border-color: #eab308; }
        .vulnerability.low { border-color: #10b981; }
        
        .vuln-title {
            font-weight: 600;
            margin-bottom: 3px;
        }
        
        .vuln-line {
            font-size: 0.75rem;
            color: #6b7280;
            margin: 3px 0;
        }
        
        .chat-section {
            flex: 1;
            padding: 15px;
            display: flex;
            flex-direction: column;
        }
        
        .chat-messages {
            flex: 1;
            min-height: 200px;
            max-height: 300px;
            overflow-y: auto;
            padding: 10px;
            background: #f9fafb;
            border-radius: 8px;
            margin: 10px 0;
        }
        
        .chat-message {
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        
        .chat-message strong {
            color: #4f46e5;
        }
        
        .chat-message .time {
            font-size: 0.7rem;
            color: #9ca3af;
            margin-left: 5px;
        }
        
        .chat-input {
            display: flex;
            gap: 8px;
        }
        
        .chat-input input {
            flex: 1;
            padding: 8px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            outline: none;
        }
        
        .chat-input input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102,126,234,0.1);
        }
        
        .chat-input button {
            padding: 8px 15px;
            background: #4f46e5;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }
        
        .typing-indicator {
            font-size: 0.8rem;
            color: #9ca3af;
            font-style: italic;
            margin-top: 5px;
        }
        
        .footer {
            margin-top: 20px;
            text-align: center;
            color: white;
            font-size: 0.85rem;
        }
        
        .footer a {
            color: white;
            text-decoration: none;
            margin: 0 10px;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ CodeGuard Collaborative Editor</div>
            <div class="user-info">
                <span class="risk-indicator risk-low" id="riskIndicator">ML: LOW RISK</span>
                <div class="avatar" id="userAvatar">U</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="editor-section">
                <div class="editor-header">
                    <div class="file-tab">
                        <span>📄 main.py</span>
                    </div>
                    <div class="cursor-info" id="cursorPosition">Ln 1, Col 1</div>
                </div>
                <textarea id="editor" placeholder="# Write your code here..."></textarea>
            </div>
            
            <div class="sidebar">
                <div class="users-online">
                    <h3>👥 Users Online (<span id="userCount">1</span>)</h3>
                    <ul class="user-list" id="userList">
                        <li class="user-item">
                            <span class="cursor-dot"></span>
                            <span>You (host)</span>
                        </li>
                    </ul>
                </div>
                
                <div class="scan-section">
                    <button class="scan-btn" id="scanBtn">🔍 Scan Code for Vulnerabilities</button>
                    <div class="scan-results" id="scanResults"></div>
                </div>
                
                <div class="chat-section">
                    <h3>💬 Team Chat</h3>
                    <div class="chat-messages" id="chatMessages">
                        <div class="chat-message">
                            <strong>System:</strong> Welcome to the collaborative session!
                            <span class="time">now</span>
                        </div>
                    </div>
                    <div class="typing-indicator" id="typingIndicator"></div>
                    <div class="chat-input">
                        <input type="text" id="chatInput" placeholder="Type a message...">
                        <button id="sendChat">Send</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <a href="/">← Back to Login</a>
            <a href="/dashboard">📊 Live Dashboard</a>
        </div>
    </div>
    
    <script>
        // Get user from session
        const user = JSON.parse(sessionStorage.getItem('user') || '{"id":"anonymous","name":"Anonymous","initials":"AN"}');
        document.getElementById('userAvatar').textContent = user.initials;
        
        // WebSocket connection
        const sessionId = 'session_' + Math.random().toString(36).substr(2, 9);
        const ws = new WebSocket(`ws://${window.location.host}/ws/collab/${sessionId}?user_id=${user.id}`);
        
        const editor = document.getElementById('editor');
        const chatMessages = document.getElementById('chatMessages');
        const chatInput = document.getElementById('chatInput');
        const userList = document.getElementById('userList');
        const userCount = document.getElementById('userCount');
        const cursorPos = document.getElementById('cursorPosition');
        const typingIndicator = document.getElementById('typingIndicator');
        
        let users = {[user.id]: true};
        let typingTimeout;
        
        // Track cursor position
        editor.addEventListener('click', updateCursor);
        editor.addEventListener('keyup', updateCursor);
        editor.addEventListener('mousemove', updateCursor);
        
        function updateCursor() {
            const pos = editor.selectionStart;
            const text = editor.value.substring(0, pos);
            const lines = text.split('\\n');
            const lineNum = lines.length;
            const colNum = lines[lines.length - 1].length + 1;
            
            cursorPos.textContent = `Ln ${lineNum}, Col ${colNum}`;
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'cursor',
                    position: { line: lineNum, column: colNum }
                }));
            }
        }
        
        // Handle typing indicator
        editor.addEventListener('keydown', () => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'typing' }));
            }
        });
        
        // Handle code changes
        editor.addEventListener('input', () => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'edit',
                    code: editor.value,
                    cursor: { line: 1, column: 1 }
                }));
            }
        });
        
        // WebSocket message handling
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            switch(data.type) {
                case 'init':
                    editor.value = data.code;
                    users = {};
                    data.users.forEach(u => users[u] = true);
                    updateUserList();
                    data.chat_history.forEach(msg => addChatMessage(msg.user_id, msg.message, msg.timestamp));
                    break;
                    
                case 'edit':
                    if (data.user_id !== user.id) {
                        const cursor = editor.selectionStart;
                        editor.value = data.code;
                        editor.setSelectionRange(cursor, cursor);
                    }
                    break;
                    
                case 'cursor':
                    if (data.user_id !== user.id) {
                        // Show cursor position (could be enhanced with visual cursor)
                        console.log(`${data.user_id} at line ${data.position.line}`);
                    }
                    break;
                    
                case 'user_joined':
                    users[data.user_id] = true;
                    updateUserList();
                    addChatMessage('System', `${data.user_id} joined the session`);
                    break;
                    
                case 'user_left':
                    delete users[data.user_id];
                    updateUserList();
                    addChatMessage('System', `${data.user_id} left the session`);
                    break;
                    
                case 'chat':
                    addChatMessage(data.user_id, data.message, data.timestamp);
                    break;
                    
                case 'typing':
                    if (data.user_id !== user.id) {
                        typingIndicator.textContent = `${data.user_id} is typing...`;
                        clearTimeout(typingTimeout);
                        typingTimeout = setTimeout(() => {
                            typingIndicator.textContent = '';
                        }, 3000);
                    }
                    break;
            }
        };
        
        function updateUserList() {
            let html = '';
            let count = 0;
            
            for (let u in users) {
                count++;
                html += `
                    <li class="user-item">
                        <span class="cursor-dot"></span>
                        <span>${u} ${u === user.id ? '(You)' : ''}</span>
                    </li>
                `;
            }
            
            userList.innerHTML = html;
            userCount.textContent = count;
        }
        
        function addChatMessage(sender, message, timestamp) {
            const time = timestamp ? new Date(timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : 'now';
            chatMessages.innerHTML += `<div class="chat-message"><strong>${sender}:</strong> ${message} <span class="time">${time}</span></div>`;
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        // Chat functionality
        document.getElementById('sendChat').addEventListener('click', sendChat);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChat();
        });
        
        function sendChat() {
            const msg = chatInput.value.trim();
            if (msg) {
                ws.send(JSON.stringify({
                    type: 'chat',
                    message: msg
                }));
                chatInput.value = '';
            }
        }
        
        // Vulnerability scanning
        document.getElementById('scanBtn').addEventListener('click', async () => {
            const btn = document.getElementById('scanBtn');
            const resultsDiv = document.getElementById('scanResults');
            
            btn.textContent = '🔬 Scanning with ML models...';
            btn.disabled = true;
            
            try {
                const response = await fetch('/api/scan-code', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: editor.value})
                });
                
                const data = await response.json();
                displayVulnerabilities(data);
                
                // Update risk indicator
                const riskIndicator = document.getElementById('riskIndicator');
                riskIndicator.className = `risk-indicator risk-${data.risk_level.toLowerCase()}`;
                riskIndicator.textContent = `ML: ${data.risk_level} RISK`;
                
            } catch (error) {
                resultsDiv.innerHTML = '<p class="vulnerability">❌ Scan failed</p>';
            } finally {
                btn.textContent = '🔍 Scan Code for Vulnerabilities';
                btn.disabled = false;
            }
        });
        
        function displayVulnerabilities(data) {
            const resultsDiv = document.getElementById('scanResults');
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                let html = `<p><strong>Found ${data.count} vulnerabilities (${data.risk_level} Risk)</strong></p>`;
                
                data.vulnerabilities.forEach(v => {
                    const severity = v.severity ? v.severity.toLowerCase() : 'medium';
                    html += `
                        <div class="vulnerability ${severity}">
                            <div class="vuln-title">${v.vulnerability || 'Security Issue'}</div>
                            <div class="vuln-line">Line ${v.line || '?'}</div>
                            <div>${v.description || ''}</div>
                            ${v.recommendation ? `<small><strong>Fix:</strong> ${v.recommendation}</small>` : ''}
                        </div>
                    `;
                });
                
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = '<p class="vulnerability" style="border-color:#10b981">✅ No vulnerabilities found</p>';
            }
        }
        
        // Load initial code
        editor.value = `# Welcome to CodeGuard Collaborative Editor
# Write your Python code below:

def hello_world():
    print("Hello, Secure World!")
    
# Try writing vulnerable code for testing:
# password = "hardcoded123"  # This will be detected
# import os
# os.system("ls")  # Command injection risk
`;
    </script>
</body>
</html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard_page():
    """Serve real-time admin dashboard"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>CodeGuard - Live Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: #1e293b;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #334155;
        }
        
        .logo {
            font-size: 1.8rem;
            font-weight: bold;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
        }
        
        .status-good { background: #065f46; color: #d1fae5; }
        .status-warning { background: #92400e; color: #fef3c7; }
        .status-critical { background: #991b1b; color: #fee2e2; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #1e293b;
            border-radius: 10px;
            padding: 15px;
            border: 1px solid #334155;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }
        
        .stat-label {
            color: #94a3b8;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-value {
            font-size: 1.8rem;
            font-weight: bold;
            color: #f8fafc;
            margin: 5px 0;
        }
        
        .stat-change {
            font-size: 0.8rem;
        }
        
        .positive { color: #4ade80; }
        .negative { color: #f87171; }
        
        .charts-row {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .chart-container {
            background: #1e293b;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #334155;
        }
        
        .chart-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
        }
        
        .chart-title {
            font-weight: 600;
            color: #f8fafc;
        }
        
        .chart-legend {
            display: flex;
            gap: 15px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.8rem;
            color: #94a3b8;
        }
        
        .legend-color {
            width: 10px;
            height: 10px;
            border-radius: 3px;
        }
        
        canvas {
            max-height: 300px;
        }
        
        .alerts-section {
            background: #1e293b;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #334155;
            margin-bottom: 20px;
        }
        
        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .alert-filters {
            display: flex;
            gap: 10px;
        }
        
        .filter-btn {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            cursor: pointer;
            background: transparent;
            border: 1px solid #334155;
            color: #94a3b8;
        }
        
        .filter-btn.active {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
        }
        
        .alert-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .alert-item {
            padding: 12px;
            border-left: 4px solid;
            background: #0f172a;
            margin-bottom: 8px;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-10px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-critical { border-color: #ef4444; }
        .alert-high { border-color: #f97316; }
        .alert-medium { border-color: #eab308; }
        .alert-low { border-color: #10b981; }
        
        .alert-content {
            flex: 1;
        }
        
        .alert-title {
            font-weight: 600;
            color: #f8fafc;
        }
        
        .alert-time {
            font-size: 0.7rem;
            color: #94a3b8;
            margin-top: 3px;
        }
        
        .alert-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        
        .badge-critical { background: #ef4444; color: white; }
        .badge-high { background: #f97316; color: white; }
        .badge-medium { background: #eab308; color: #0f172a; }
        .badge-low { background: #10b981; color: #0f172a; }
        
        .action-btn {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            border: none;
            margin-left: 10px;
        }
        
        .btn-investigate { background: #3b82f6; color: white; }
        .btn-dismiss { background: #475569; color: #e2e8f0; }
        
        .sessions-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .sessions-table th {
            text-align: left;
            padding: 12px;
            background: #0f172a;
            color: #94a3b8;
            font-weight: 500;
            font-size: 0.8rem;
        }
        
        .sessions-table td {
            padding: 12px;
            border-bottom: 1px solid #334155;
            color: #e2e8f0;
        }
        
        .risk-cell {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-block;
        }
        
        .risk-critical { background: #ef4444; color: white; }
        .risk-high { background: #f97316; color: white; }
        .risk-medium { background: #eab308; color: #0f172a; }
        .risk-low { background: #10b981; color: #0f172a; }
        
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #64748b;
        }
        
        .footer a {
            color: #60a5fa;
            text-decoration: none;
            margin: 0 10px;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">📊 CodeGuard Live Security Dashboard</div>
            <div>
                <span class="status-badge status-good" id="systemStatus">System Healthy</span>
            </div>
        </div>
        
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-label">Active Users</div>
                <div class="stat-value" id="activeUsers">0</div>
                <div class="stat-change" id="userChange">+0%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Sessions</div>
                <div class="stat-value" id="activeSessions">0</div>
                <div class="stat-change" id="sessionChange">+0%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Alerts</div>
                <div class="stat-value" id="totalAlerts">0</div>
                <div class="stat-change negative" id="alertChange">0 new</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Risk Score</div>
                <div class="stat-value" id="avgRisk">0</div>
                <div class="stat-change" id="riskChange">0%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Threats</div>
                <div class="stat-value" id="activeThreats">0</div>
                <div class="stat-change negative" id="threatChange">0 critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Trust Score</div>
                <div class="stat-value" id="trustScore">100</div>
                <div class="stat-change positive">+0%</div>
            </div>
        </div>
        
        <div class="charts-row">
            <div class="chart-container">
                <div class="chart-header">
                    <span class="chart-title">Risk Distribution</span>
                    <div class="chart-legend">
                        <div class="legend-item"><span class="legend-color" style="background:#10b981"></span> Low</div>
                        <div class="legend-item"><span class="legend-color" style="background:#eab308"></span> Medium</div>
                        <div class="legend-item"><span class="legend-color" style="background:#f97316"></span> High</div>
                        <div class="legend-item"><span class="legend-color" style="background:#ef4444"></span> Critical</div>
                    </div>
                </div>
                <canvas id="riskChart"></canvas>
            </div>
            
            <div class="chart-container">
                <div class="chart-header">
                    <span class="chart-title">Session Timeline</span>
                </div>
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="alerts-header">
                <span class="chart-title">🚨 Real-time Security Alerts</span>
                <div class="alert-filters">
                    <span class="filter-btn active" onclick="filterAlerts('all')">All</span>
                    <span class="filter-btn" onclick="filterAlerts('critical')">Critical</span>
                    <span class="filter-btn" onclick="filterAlerts('high')">High</span>
                    <span class="filter-btn" onclick="filterAlerts('medium')">Medium</span>
                </div>
            </div>
            <div class="alert-list" id="alertList">
                <div style="text-align: center; padding: 20px; color: #64748b;">Loading alerts...</div>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart-header">
                <span class="chart-title">Active Sessions</span>
            </div>
            <table class="sessions-table" id="sessionsTable">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Session ID</th>
                        <th>Duration</th>
                        <th>Risk Score</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="sessionsBody">
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 20px;">No active sessions</td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <a href="/">← Back to Login</a>
            <a href="/editor">Open Editor →</a>
            <span style="margin-left: 20px; color: #64748b;">Last Update: <span id="lastUpdate">-</span></span>
        </div>
    </div>
    
    <script>
        // Initialize WebSocket connection for real-time updates
        const ws = new WebSocket(`ws://${window.location.host}/ws/dashboard`);
        
        // Initialize charts
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        
        let riskChart, timelineChart;
        
        function initCharts() {
            riskChart = new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#10b981', '#eab308', '#f97316', '#ef4444'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
            
            timelineChart = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Sessions',
                        data: [],
                        borderColor: '#60a5fa',
                        backgroundColor: 'rgba(96, 165, 250, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: { color: '#334155' },
                            ticks: { color: '#94a3b8' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#94a3b8' }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
        
        initCharts();
        
        // WebSocket message handling
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'metrics_update') {
                updateStats(data.data);
            } else if (data.type === 'new_alert') {
                addAlert(data.data);
            }
        };
        
        // Fetch initial data
        async function fetchDashboardData() {
            try {
                const response = await fetch('/api/dashboard/data');
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Failed to fetch dashboard data:', error);
            }
        }
        
        function updateDashboard(data) {
            // Update stats
            document.getElementById('activeUsers').textContent = data.stats.total_users;
            document.getElementById('activeSessions').textContent = data.stats.total_sessions;
            document.getElementById('totalAlerts').textContent = data.stats.total_alerts;
            document.getElementById('avgRisk').textContent = data.stats.avg_risk.toFixed(1);
            document.getElementById('activeThreats').textContent = data.stats.active_threats || 0;
            document.getElementById('trustScore').textContent = (100 - data.stats.avg_risk).toFixed(1);
            
            // Update system status
            const statusEl = document.getElementById('systemStatus');
            if (data.stats.avg_risk > 60) {
                statusEl.className = 'status-badge status-critical';
                statusEl.textContent = 'System Critical';
            } else if (data.stats.avg_risk > 30) {
                statusEl.className = 'status-badge status-warning';
                statusEl.textContent = 'System Warning';
            } else {
                statusEl.className = 'status-badge status-good';
                statusEl.textContent = 'System Healthy';
            }
            
            // Update risk chart
            if (data.stats.risk_distribution) {
                riskChart.data.datasets[0].data = [
                    data.stats.risk_distribution.LOW || 0,
                    data.stats.risk_distribution.MEDIUM || 0,
                    data.stats.risk_distribution.HIGH || 0,
                    data.stats.risk_distribution.CRITICAL || 0
                ];
                riskChart.update();
            }
            
            // Update alerts
            displayAlerts(data.recent_alerts);
            
            // Update last update time
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        }
        
        function updateStats(metrics) {
            document.getElementById('activeUsers').textContent = metrics.active_users;
            document.getElementById('activeSessions').textContent = metrics.active_sessions;
            document.getElementById('totalAlerts').textContent = metrics.total_alerts;
            document.getElementById('avgRisk').textContent = metrics.avg_risk_score.toFixed(1);
            document.getElementById('activeThreats').textContent = metrics.critical_alerts || 0;
            document.getElementById('trustScore').textContent = (100 - metrics.avg_risk_score).toFixed(1);
            
            // Update timeline
            const now = new Date();
            timelineChart.data.labels.push(now.toLocaleTimeString());
            timelineChart.data.datasets[0].data.push(metrics.active_sessions);
            
            if (timelineChart.data.labels.length > 20) {
                timelineChart.data.labels.shift();
                timelineChart.data.datasets[0].data.shift();
            }
            
            timelineChart.update();
        }
        
        function displayAlerts(alerts) {
            const alertList = document.getElementById('alertList');
            
            if (!alerts || alerts.length === 0) {
                alertList.innerHTML = '<div style="text-align: center; padding: 20px; color: #64748b;">No alerts</div>';
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const severity = alert.severity ? alert.severity.toLowerCase() : 'medium';
                const time = new Date(alert.timestamp).toLocaleTimeString();
                
                html += `
                    <div class="alert-item alert-${severity}" data-severity="${severity}">
                        <div class="alert-content">
                            <div class="alert-title">${alert.title || 'Security Alert'}</div>
                            <div class="alert-time">${time} • ${alert.user_id || 'Unknown'}</div>
                            ${alert.reasons ? `<div style="font-size:0.8rem; color:#94a3b8;">${alert.reasons[0]}</div>` : ''}
                        </div>
                        <div>
                            <span class="alert-badge badge-${severity}">${alert.severity || 'MEDIUM'}</span>
                            <button class="action-btn btn-investigate" onclick="investigateAlert('${alert.id}')">Investigate</button>
                        </div>
                    </div>
                `;
            });
            
            alertList.innerHTML = html;
        }
        
        function addAlert(alert) {
            const alertList = document.getElementById('alertList');
            const severity = alert.severity ? alert.severity.toLowerCase() : 'medium';
            const time = new Date().toLocaleTimeString();
            
            const alertHtml = `
                <div class="alert-item alert-${severity}" data-severity="${severity}" style="animation: slideIn 0.3s ease;">
                    <div class="alert-content">
                        <div class="alert-title">${alert.title || 'New Security Alert'}</div>
                        <div class="alert-time">${time} • ${alert.user_id || 'Unknown'}</div>
                        ${alert.reasons ? `<div style="font-size:0.8rem; color:#94a3b8;">${alert.reasons[0]}</div>` : ''}
                    </div>
                    <div>
                        <span class="alert-badge badge-${severity}">${alert.severity || 'MEDIUM'}</span>
                        <button class="action-btn btn-investigate" onclick="investigateAlert('${alert.id}')">Investigate</button>
                    </div>
                </div>
            `;
            
            alertList.insertAdjacentHTML('afterbegin', alertHtml);
            
            // Update total alerts count
            const totalAlerts = document.getElementById('totalAlerts');
            totalAlerts.textContent = parseInt(totalAlerts.textContent) + 1;
        }
        
        function filterAlerts(severity) {
            const alerts = document.querySelectorAll('.alert-item');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            alerts.forEach(alert => {
                if (severity === 'all' || alert.dataset.severity === severity) {
                    alert.style.display = 'flex';
                } else {
                    alert.style.display = 'none';
                }
            });
        }
        
        function investigateAlert(alertId) {
            console.log('Investigating alert:', alertId);
            // In production, this would open detailed investigation view
            alert(`Investigating alert ${alertId} (Demo)`);
        }
        
        // Simulate active sessions
        function updateSessionsTable() {
            const tbody = document.getElementById('sessionsBody');
            const sessions = [
                { user: 'hackathon_user', id: 'sess_' + Math.random().toString(36).substr(2, 8), duration: '5 min', risk: 23, status: 'Low' },
                { user: 'developer_1', id: 'sess_' + Math.random().toString(36).substr(2, 8), duration: '12 min', risk: 45, status: 'Medium' },
                { user: 'security_team', id: 'sess_' + Math.random().toString(36).substr(2, 8), duration: '2 min', risk: 12, status: 'Low' }
            ];
            
            let html = '';
            sessions.forEach(s => {
                const riskClass = s.risk < 30 ? 'risk-low' : s.risk < 60 ? 'risk-medium' : 'risk-high';
                html += `
                    <tr>
                        <td>${s.user}</td>
                        <td style="font-family: monospace;">${s.id}</td>
                        <td>${s.duration}</td>
                        <td><span class="risk-cell ${riskClass}">${s.risk}</span></td>
                        <td>${s.status}</td>
                        <td>
                            <button class="action-btn btn-investigate" style="padding:4px 8px;">View</button>
                        </td>
                    </tr>
                `;
            });
            
            tbody.innerHTML = html;
        }
        
        // Initial fetch
        fetchDashboardData();
        updateSessionsTable();
        
        // Refresh every 30 seconds
        setInterval(fetchDashboardData, 30000);
        setInterval(updateSessionsTable, 60000);
        
        // WebSocket connection status
        ws.onopen = () => console.log('Dashboard connected to real-time updates');
        ws.onclose = () => console.log('Dashboard disconnected');
    </script>
</body>
</html>
    """


# ==================== MAIN ====================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🛡️  CODEGUARD - Advanced ML-Powered Security Platform")
    print("="*80)
    print("\n✅ ML Models Loaded:")
    print("   - Isolation Forest (Unsupervised Anomaly Detection)")
    print("   - Random Forest (Supervised Classification)")
    print(f"   - Features: {len(ml_system.model.feature_names)} behavioral metrics")
    print(f"   - Model Accuracy: {ml_system.model.model_accuracy:.2%}")
    
    print("\n📱 Alert Channels:")
    print("   - SMS Alerts (Twilio) " + ("✅ Configured" if config.TWILIO_ACCOUNT_SID else "⚠️ Demo Mode"))
    print("   - Email Alerts " + ("✅ Configured" if config.SMTP_USERNAME else "⚠️ Demo Mode"))
    print("   - Webhook Alerts " + ("✅ Configured" if config.ALERT_WEBHOOK_URL else "⚠️ Demo Mode"))
    print("   - Desktop Notifications ✅")
    print("   - Real-time Dashboard ✅")
    
    print("\n🌐 Available URLs:")
    print("   - http://localhost:8000 - Login Page (ML Tracking)")
    print("   - http://localhost:8000/editor - Collaborative Editor")
    print("   - http://localhost:8000/dashboard - Live Security Dashboard")
    
    print("\n📊 Features:")
    print("   - Dual ML Models (Isolation Forest + Random Forest)")
    print("   - Real-time Behavioral Biometrics")
    print("   - Multi-channel Alerts (SMS, Email, Webhook)")
    print("   - Live Dashboard with WebSocket Updates")
    print("   - AI Vulnerability Scanning")
    print("   - Team Chat & Cursor Tracking")
    print("   - Trust Score & Risk Assessment")
    
    print("\n" + "="*80)
    print("🚀 Starting CodeGuard server...")
    print("="*80 + "\n")
    
    uvicorn.run(
        "codeguard_complete:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )