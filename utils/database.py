import sqlite3
import json
import hashlib
from datetime import datetime
import threading

class DetectionDatabase:
    def __init__(self, db_path="detection_results.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Create database table if it doesn't exist"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT (datetime('now', '+8 hours')),
                    filename TEXT NOT NULL,
                    file_hash TEXT,
                    source TEXT,
                    prediction INTEGER,
                    analysis_result TEXT
                )
            ''')
            conn.commit()
            conn.close()
    
    def store_result(self, filename, file_hash, source, prediction, analysis_result):
        """Store analysis result in database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            # Store Malaysia time (UTC+8)
            malaysia_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn.execute('''
                INSERT INTO detections 
                (timestamp, filename, file_hash, source, prediction, analysis_result)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (malaysia_time, filename, file_hash, source, prediction, json.dumps(analysis_result)))
            conn.commit()
            conn.close()
    
    def get_recent_results(self, limit=10):
        """Get recent detection results"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                SELECT id, timestamp, filename, source, prediction, analysis_result
                FROM detections 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            results = cursor.fetchall()
            conn.close()
            
            # Convert to list of dictionaries
            return [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'filename': row[2],
                    'source': row[3],
                    'prediction': row[4],
                    'analysis_result': json.loads(row[5])
                }
                for row in results
            ]
    
    def get_all_results(self):
        """Get all detection results for history page"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                SELECT id, timestamp, filename, source, prediction
                FROM detections 
                ORDER BY timestamp DESC
            ''')
            results = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'filename': row[2],
                    'source': row[3],
                    'prediction': row[4]
                }
                for row in results
            ]
    
    def get_result_by_id(self, result_id):
        """Get detailed result by ID"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute('''
                SELECT * FROM detections WHERE id = ?
            ''', (result_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'id': row[0],
                    'timestamp': row[1],
                    'filename': row[2],
                    'file_hash': row[4],
                    'source': row[5],
                    'prediction': row[6],
                    'analysis_result': json.loads(row[7])
                }
            return None

# Helper function to calculate file hash
def calculate_file_hash(file_path):
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except:
        return None