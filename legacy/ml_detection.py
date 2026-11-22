import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import json
import hashlib
import pickle
import os
from typing import Dict, List, Tuple
import asyncio
from collections import defaultdict

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.user_profiles = {}
        self.session_history = defaultdict(list)
        self.model_path = "models/anomaly_model.pkl"
        self.load_model()
        
    def load_model(self):
        """Load pre-trained model if exists"""
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
    
    def save_model(self):
        """Save trained model"""
        os.makedirs("models", exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
    
    def extract_features(self, session_data: Dict) -> np.array:
        """Extract features from session for ML detection"""
        features = []
        
        # Time-based features
        current_time = datetime.now()
        features.append(current_time.hour)  # Hour of day
        features.append(current_time.weekday())  # Day of week
        
        # Session features
        features.append(session_data.get('typing_speed', 0))  # Characters per minute
        features.append(session_data.get('mouse_movements', 0))  # Mouse movement count
        features.append(session_data.get('key_presses', 0))  # Key press count
        features.append(session_data.get('paste_events', 0))  # Paste events
        features.append(session_data.get('copy_events', 0))  # Copy events
        features.append(session_data.get('tab_switches', 0))  # Tab switches
        features.append(session_data.get('focus_losses', 0))  # Focus losses
        
        # Code patterns
        features.append(session_data.get('code_length', 0))
        features.append(session_data.get('comment_ratio', 0))  # Comments vs code
        features.append(session_data.get('import_count', 0))
        
        # Network features
        features.append(session_data.get('request_frequency', 0))  # API requests per minute
        features.append(session_data.get('unique_ips', 1))  # Number of unique IPs
        
        return np.array(features).reshape(1, -1)
    
    def detect_anomaly(self, user_id: str, session_data: Dict) -> Tuple[bool, float, List[str]]:
        """Detect if current session is anomalous"""
        features = self.extract_features(session_data)
        
        # Scale features
        if hasattr(self, 'scaler'):
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features
        
        # Predict anomaly (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(features_scaled)[0]
        score = self.model.score_samples(features_scaled)[0]
        
        is_anomaly = prediction == -1
        
        # Get anomaly reasons
        reasons = []
        if is_anomaly:
            reasons = self.get_anomaly_reasons(features[0], session_data)
        
        # Store in history
        self.session_history[user_id].append({
            'timestamp': datetime.now(),
            'is_anomaly': is_anomaly,
            'score': float(score)
        })
        
        return is_anomaly, float(score), reasons
    
    def get_anomaly_reasons(self, features: np.array, session_data: Dict) -> List[str]:
        """Get human-readable reasons for anomaly"""
        reasons = []
        
        # Check unusual hours
        hour = features[0]
        if hour < 6 or hour > 22:
            reasons.append(f"Unusual login time: {int(hour)}:00")
        
        # Check unusual behavior
        if session_data.get('paste_events', 0) > 50:
            reasons.append("Unusual number of paste events - possible data exfiltration")
        
        if session_data.get('copy_events', 0) > 100:
            reasons.append("Excessive copy operations detected")
        
        if session_data.get('tab_switches', 0) > 30:
            reasons.append("Multiple tab switches - possible unauthorized access")
        
        if session_data.get('request_frequency', 0) > 100:
            reasons.append("Unusual API request frequency - possible automated attack")
        
        return reasons
    
    def train_model(self, training_data: List[Dict]):
        """Train the anomaly detection model"""
        features_list = []
        for data in training_data:
            features = self.extract_features(data)
            features_list.append(features[0])
        
        X = np.array(features_list)
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled)
        self.save_model()

class BehavioralBiometrics:
    """Track user behavior patterns"""
    
    def __init__(self):
        self.user_patterns = defaultdict(dict)
        self.typing_profiles = {}
        
    def analyze_typing_pattern(self, user_id: str, keystrokes: List[Dict]) -> Dict:
        """Analyze typing patterns for biometric identification"""
        if len(keystrokes) < 10:
            return {'confidence': 0, 'match': False}
        
        # Calculate typing metrics
        durations = []
        intervals = []
        
        for i in range(1, len(keystrokes)):
            key1 = keystrokes[i-1]
            key2 = keystrokes[i]
            
            # Time key was held down
            if 'duration' in key1:
                durations.append(key1['duration'])
            
            # Time between keys
            interval = (datetime.fromisoformat(key2['timestamp']) - 
                       datetime.fromisoformat(key1['timestamp'])).total_seconds() * 1000
            intervals.append(interval)
        
        # Calculate statistics
        avg_duration = np.mean(durations) if durations else 0
        avg_interval = np.mean(intervals) if intervals else 0
        duration_std = np.std(durations) if durations else 0
        interval_std = np.std(intervals) if intervals else 0
        
        current_profile = {
            'avg_duration': avg_duration,
            'avg_interval': avg_interval,
            'duration_std': duration_std,
            'interval_std': interval_std
        }
        
        # Compare with stored profile
        if user_id in self.typing_profiles:
            stored = self.typing_profiles[user_id]
            confidence = self.compare_profiles(current_profile, stored)
            return {
                'confidence': confidence,
                'match': confidence > 0.7,
                'profile': current_profile
            }
        else:
            # Store first profile
            self.typing_profiles[user_id] = current_profile
            return {'confidence': 1.0, 'match': True, 'profile': current_profile}
    
    def compare_profiles(self, profile1: Dict, profile2: Dict) -> float:
        """Compare two typing profiles"""
        weights = {
            'avg_duration': 0.3,
            'avg_interval': 0.3,
            'duration_std': 0.2,
            'interval_std': 0.2
        }
        
        similarity = 0
        total_weight = 0
        
        for key, weight in weights.items():
            if key in profile1 and key in profile2:
                # Normalize difference
                diff = abs(profile1[key] - profile2[key])
                max_val = max(profile1[key], profile2[key]) or 1
                norm_diff = min(diff / max_val, 1)
                similarity += weight * (1 - norm_diff)
                total_weight += weight
        
        return similarity / total_weight if total_weight > 0 else 0

class SessionMonitor:
    """Monitor sessions in real-time for suspicious activity"""
    
    def __init__(self):
        self.active_sessions = {}
        self.anomaly_detector = AnomalyDetector()
        self.behavioral_biometrics = BehavioralBiometrics()
        self.alert_callbacks = []
        
    def register_alert_callback(self, callback):
        """Register callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    async def track_session(self, session_id: str, user_id: str, event_data: Dict):
        """Track session events in real-time"""
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'start_time': datetime.now(),
                'events': [],
                'risk_score': 0,
                'typing_data': [],
                'anomalies': []
            }
        
        session = self.active_sessions[session_id]
        session['events'].append({
            'timestamp': datetime.now(),
            'type': event_data.get('type'),
            'data': event_data
        })
        
        # Analyze different event types
        if event_data.get('type') == 'keystroke':
            session['typing_data'].append({
                'key': event_data.get('key'),
                'duration': event_data.get('duration', 0),
                'timestamp': event_data.get('timestamp')
            })
            
            # Periodic typing analysis
            if len(session['typing_data']) % 50 == 0:
                typing_analysis = self.behavioral_biometrics.analyze_typing_pattern(
                    user_id, session['typing_data'][-100:]
                )
                
                if not typing_analysis['match']:
                    await self.trigger_alert({
                        'type': 'biometric_mismatch',
                        'user_id': user_id,
                        'session_id': session_id,
                        'confidence': typing_analysis['confidence'],
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Periodic anomaly detection
        if len(session['events']) % 20 == 0:
            session_features = self.extract_session_features(session)
            is_anomaly, score, reasons = self.anomaly_detector.detect_anomaly(
                user_id, session_features
            )
            
            if is_anomaly:
                session['anomalies'].append({
                    'timestamp': datetime.now(),
                    'score': score,
                    'reasons': reasons
                })
                
                await self.trigger_alert({
                    'type': 'anomaly_detected',
                    'user_id': user_id,
                    'session_id': session_id,
                    'score': score,
                    'reasons': reasons,
                    'timestamp': datetime.now().isoformat()
                })
    
    def extract_session_features(self, session: Dict) -> Dict:
        """Extract features from session for analysis"""
        events = session['events']
        recent_events = [e for e in events if 
                        (datetime.now() - e['timestamp']).total_seconds() < 300]  # Last 5 minutes
        
        # Calculate metrics
        paste_events = sum(1 for e in recent_events if e['type'] == 'paste')
        copy_events = sum(1 for e in recent_events if e['type'] == 'copy')
        key_presses = sum(1 for e in recent_events if e['type'] == 'keystroke')
        
        # Calculate typing speed (chars per minute)
        if len(recent_events) > 1:
            time_span = (recent_events[-1]['timestamp'] - recent_events[0]['timestamp']).total_seconds()
            typing_speed = (key_presses / time_span) * 60 if time_span > 0 else 0
        else:
            typing_speed = 0
        
        return {
            'typing_speed': typing_speed,
            'paste_events': paste_events,
            'copy_events': copy_events,
            'key_presses': key_presses,
            'tab_switches': sum(1 for e in recent_events if e['type'] == 'tab_switch'),
            'focus_losses': sum(1 for e in recent_events if e['type'] == 'focus_loss'),
            'code_length': session.get('code_length', 0),
            'request_frequency': len(recent_events) / 5  # Requests per minute
        }
    
    async def trigger_alert(self, alert_data: Dict):
        """Trigger security alerts"""
        for callback in self.alert_callbacks:
            await callback(alert_data)
        
        # Log alert
        print(f"🚨 Security Alert: {alert_data}")

session_monitor = SessionMonitor()