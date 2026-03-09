"""
ML-Based Anomaly Detection Engine
Local AI-Powered Security Operations Center

Machine learning-based anomaly detection for security events.
"""

import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from collections import defaultdict, deque
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

logger = structlog.get_logger()


class AnomalyDetector:
    """ML-based anomaly detection for security events."""
    
    def __init__(self, data_dir: str = "./data/anomaly_detection"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Event storage for ML training
        self.event_buffer: deque = deque(maxlen=50000)
        self.baseline_events: List[Dict[str, Any]] = []
        
        # ML models
        self.isolation_forest: Optional[IsolationForest] = None
        self.dbscan: Optional[DBSCAN] = None
        self.scaler: Optional[StandardScaler] = None
        
        # Baseline statistics
        self.baseline_stats: Dict[str, Any] = {}
        self.thresholds: Dict[str, float] = {}
        
        # Anomaly alerts
        self.anomalies: List[Dict[str, Any]] = []
        self.max_anomalies = 1000
        
        # Feature configuration
        self.numeric_features = [
            'bytes_in', 'bytes_out', 'packets_in', 'packets_out',
            'duration', 'port', 'failed_attempts', 'event_count',
        ]
        
        self.categorical_features = [
            'protocol', 'event_type', 'source_type', 'action',
        ]
        
        logger.info("AnomalyDetector initialized")
    
    def add_event(self, event: Dict[str, Any]):
        """
        Add event to buffer for analysis.
        
        Args:
            event: Security event dictionary
        """
        self.event_buffer.append(event)
        
        # Retrain model periodically
        if len(self.event_buffer) % 1000 == 0 and len(self.event_buffer) >= 5000:
            self._retrain_model()
    
    def _extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract numeric features from events for ML.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Feature matrix
        """
        features = []
        
        for event in events:
            feature_vector = []
            
            # Numeric features
            for feature in self.numeric_features:
                value = event.get(feature, 0)
                if isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            # Categorical features (one-hot encoded)
            for feature in self.categorical_features:
                value = event.get(feature, '')
                # Simple hash-based encoding
                encoded = hash(str(value)) % 100 / 100.0
                feature_vector.append(encoded)
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def _retrain_model(self):
        """Retrain ML models on recent events."""
        if len(self.event_buffer) < 1000:
            return
        
        try:
            logger.info("Retraining anomaly detection models")
            
            # Extract features
            events = list(self.event_buffer)
            X = self._extract_features(events)
            
            # Fit scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Fit Isolation Forest
            self.isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                n_jobs=-1,
            )
            self.isolation_forest.fit(X_scaled)
            
            # Fit DBSCAN for clustering
            self.dbscan = DBSCAN(eps=0.5, min_samples=10)
            self.dbscan.fit(X_scaled)
            
            # Store baseline
            self.baseline_events = events[-1000:]
            self.baseline_stats = self._calculate_baseline_stats(events)
            
            # Calculate thresholds
            scores = self.isolation_forest.decision_function(X_scaled)
            self.thresholds['anomaly'] = np.percentile(scores, 5)
            
            logger.info(
                "Models retrained",
                events=len(events),
                threshold=self.thresholds['anomaly'],
            )
            
        except Exception as e:
            logger.error(f"Failed to retrain models: {str(e)}")
    
    def _calculate_baseline_stats(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate baseline statistics from events."""
        stats = {
            'avg_bytes_in': 0,
            'avg_bytes_out': 0,
            'avg_events_per_hour': 0,
            'common_protocols': [],
            'common_event_types': [],
        }
        
        if not events:
            return stats
        
        # Calculate averages
        bytes_in = [e.get('bytes_in', 0) for e in events if isinstance(e.get('bytes_in'), (int, float))]
        bytes_out = [e.get('bytes_out', 0) for e in events if isinstance(e.get('bytes_out'), (int, float))]
        
        if bytes_in:
            stats['avg_bytes_in'] = np.mean(bytes_in)
        if bytes_out:
            stats['avg_bytes_out'] = np.mean(bytes_out)
        
        # Calculate event rate
        if len(events) >= 2:
            timestamps = [e.get('timestamp', '') for e in events]
            # Simplified - assume events are roughly hourly
            stats['avg_events_per_hour'] = len(events) / max(1, len(timestamps) // 100)
        
        # Common protocols
        protocols = [e.get('protocol', '') for e in events if e.get('protocol')]
        if protocols:
            protocol_counts = defaultdict(int)
            for p in protocols:
                protocol_counts[p] += 1
            stats['common_protocols'] = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Common event types
        event_types = [e.get('event_type', '') for e in events if e.get('event_type')]
        if event_types:
            type_counts = defaultdict(int)
            for t in event_types:
                type_counts[t] += 1
            stats['common_event_types'] = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return stats
    
    def detect_anomaly(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect if an event is anomalous.
        
        Args:
            event: Security event
            
        Returns:
            Anomaly details if detected, None otherwise
        """
        if self.isolation_forest is None or self.scaler is None:
            # Not enough data for ML, use rule-based detection
            return self._rule_based_anomaly(event)
        
        try:
            # Extract features
            X = self._extract_features([event])
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly score
            score = self.isolation_forest.decision_function(X_scaled)[0]
            prediction = self.isolation_forest.predict(X_scaled)[0]
            
            # -1 = anomaly, 1 = normal
            if prediction == -1 or score < self.thresholds.get('anomaly', -0.5):
                anomaly = {
                    'event': event,
                    'anomaly_score': float(score),
                    'threshold': self.thresholds.get('anomaly', -0.5),
                    'detection_type': 'ml_isolation_forest',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'severity': self._calculate_anomaly_severity(score),
                }
                
                self.anomalies.append(anomaly)
                if len(self.anomalies) > self.max_anomalies:
                    self.anomalies.pop(0)
                
                return anomaly
            
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {str(e)}")
        
        return None
    
    def _rule_based_anomaly(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule-based anomaly detection (fallback when ML not ready).
        
        Args:
            event: Security event
            
        Returns:
            Anomaly details if detected
        """
        anomalies = []
        
        # Check for unusual byte transfers
        bytes_out = event.get('bytes_out', 0)
        if isinstance(bytes_out, (int, float)) and bytes_out > 100 * 1024 * 1024:  # 100MB
            anomalies.append({
                'type': 'high_outbound_traffic',
                'value': bytes_out,
                'threshold': 100 * 1024 * 1024,
            })
        
        # Check for unusual ports
        port = event.get('port', 0)
        unusual_ports = [4444, 5555, 6666, 31337, 12345]
        if port in unusual_ports:
            anomalies.append({
                'type': 'suspicious_port',
                'value': port,
            })
        
        # Check for high failed attempts
        failed = event.get('failed_attempts', 0)
        if isinstance(failed, (int, float)) and failed > 10:
            anomalies.append({
                'type': 'high_failed_attempts',
                'value': failed,
                'threshold': 10,
            })
        
        if anomalies:
            anomaly = {
                'event': event,
                'anomalies': anomalies,
                'detection_type': 'rule_based',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'severity': 'high' if len(anomalies) > 1 else 'medium',
            }
            
            self.anomalies.append(anomaly)
            if len(self.anomalies) > self.max_anomalies:
                self.anomalies.pop(0)
            
            return anomaly
        
        return None
    
    def _calculate_anomaly_severity(self, score: float) -> str:
        """Calculate severity based on anomaly score."""
        if score < -1.0:
            return 'critical'
        elif score < -0.7:
            return 'high'
        elif score < -0.5:
            return 'medium'
        else:
            return 'low'
    
    def detect_behavioral_anomaly(
        self,
        entity: str,
        entity_type: str,
        current_metrics: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Detect behavioral anomalies for an entity.
        
        Args:
            entity: Entity identifier (IP, user, host)
            entity_type: Type of entity (ip, user, host)
            current_metrics: Current behavior metrics
            
        Returns:
            Anomaly details if detected
        """
        # Calculate baseline for this entity
        entity_events = [
            e for e in self.event_buffer
            if e.get(entity_type) == entity
        ]
        
        if len(entity_events) < 10:
            return None
        
        # Compare current to baseline
        anomalies = []
        
        # Check bytes deviation
        baseline_bytes = np.mean([e.get('bytes_out', 0) for e in entity_events])
        current_bytes = current_metrics.get('bytes_out', 0)
        
        if baseline_bytes > 0 and current_bytes > baseline_bytes * 5:
            anomalies.append({
                'type': 'traffic_spike',
                'baseline': baseline_bytes,
                'current': current_bytes,
                'deviation': current_bytes / baseline_bytes,
            })
        
        # Check time-of-day anomaly
        current_hour = datetime.utcnow().hour
        entity_hours = []
        for e in entity_events:
            try:
                ts = datetime.fromisoformat(e.get('timestamp', '').replace('Z', '+00:00'))
                entity_hours.append(ts.hour)
            except:
                pass
        
        if entity_hours:
            avg_hour = np.mean(entity_hours)
            hour_diff = abs(current_hour - avg_hour)
            if hour_diff > 6:  # Activity at unusual time
                anomalies.append({
                    'type': 'unusual_time',
                    'current_hour': current_hour,
                    'baseline_avg_hour': avg_hour,
                })
        
        if anomalies:
            return {
                'entity': entity,
                'entity_type': entity_type,
                'anomalies': anomalies,
                'detection_type': 'behavioral',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'severity': 'high' if len(anomalies) > 1 else 'medium',
            }
        
        return None
    
    def get_anomalies(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        detection_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get detected anomalies."""
        anomalies = self.anomalies
        
        if severity:
            anomalies = [a for a in anomalies if a.get('severity') == severity]
        
        if detection_type:
            anomalies = [a for a in anomalies if a.get('detection_type') == detection_type]
        
        # Sort by timestamp (newest first)
        anomalies.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return anomalies[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get anomaly detection statistics."""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        
        for anomaly in self.anomalies:
            by_severity[anomaly.get('severity', 'unknown')] += 1
            by_type[anomaly.get('detection_type', 'unknown')] += 1
        
        return {
            'total_anomalies': len(self.anomalies),
            'by_severity': dict(by_severity),
            'by_detection_type': dict(by_type),
            'model_trained': self.isolation_forest is not None,
            'baseline_events': len(self.baseline_events),
            'event_buffer_size': len(self.event_buffer),
            'baseline_stats': self.baseline_stats,
        }
    
    def save_model(self):
        """Save model and baseline to disk."""
        import pickle
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"anomaly_model_{timestamp}.pkl"
        
        model_data = {
            'isolation_forest': self.isolation_forest,
            'dbscan': self.dbscan,
            'scaler': self.scaler,
            'baseline_stats': self.baseline_stats,
            'thresholds': self.thresholds,
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Saved anomaly model to {filename}")
    
    def load_model(self, filename: Optional[str] = None):
        """Load model from disk."""
        import pickle
        
        if filename is None:
            # Find latest model
            models = sorted(self.data_dir.glob("anomaly_model_*.pkl"))
            if models:
                filename = models[-1]
            else:
                logger.warning("No saved model found")
                return
        
        try:
            with open(filename, 'rb') as f:
                model_data = pickle.load(f)
            
            self.isolation_forest = model_data.get('isolation_forest')
            self.dbscan = model_data.get('dbscan')
            self.scaler = model_data.get('scaler')
            self.baseline_stats = model_data.get('baseline_stats', {})
            self.thresholds = model_data.get('thresholds', {})
            
            logger.info(f"Loaded anomaly model from {filename}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")


# Global anomaly detector instance
anomaly_detector = AnomalyDetector()
