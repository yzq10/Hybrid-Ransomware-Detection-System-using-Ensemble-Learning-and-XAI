import os
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

from .database import DetectionDatabase, calculate_file_hash

logger = logging.getLogger(__name__)

# Configuration
MONITORED_PATHS = [
    r"C:\Users\Yap Zhan Quan\Downloads"
]

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys'}
MIN_FILE_SIZE = 1024  # 1KB minimum
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB maximum

# Global variables
observer = None
monitoring_active = False
db = None

class RansomwareFileHandler(FileSystemEventHandler):
    """Handle file system events and trigger analysis"""
    
    def __init__(self, detector, dynamic_detector, static_feature_mapping=None):
        self.detector = detector
        self.dynamic_detector = dynamic_detector
        self.static_feature_mapping = static_feature_mapping  # FIXED: Store feature mapping path
        
    def on_created(self, event):
        """Called when a new file is created"""
        if not event.is_directory:
            self.process_file(event.src_path)
    
    def on_moved(self, event):
        """Called when a file is moved/renamed"""
        if not event.is_directory:
            self.process_file(event.dest_path)
    
    def process_file(self, file_path):
        """Process detected file through analysis pipeline"""
        try:
            file_path = Path(file_path)
            
            # Check if file should be analyzed
            if not self.should_analyze(file_path):
                return
            
            logger.info(f"🔍 Auto-detected file: {file_path}")
            
            # ENHANCED: Better wait strategy and file handle checking
            time.sleep(5)  # Initial wait
            
            # Check if file is still being written to
            initial_size = file_path.stat().st_size
            time.sleep(2)  # Wait a bit more
            final_size = file_path.stat().st_size
            
            if initial_size != final_size:
                logger.info(f"⏳ File still being written, waiting longer...")
                time.sleep(5)  # Wait even more if file is still changing
            
            # ENHANCED: Test file access before analysis
            try:
                with open(file_path, 'rb') as test_file:
                    test_file.read(1024)  # Try to read first 1KB
            except (PermissionError, IOError) as e:
                logger.warning(f"⚠️ File access test failed, skipping: {e}")
                return
            
            # Analyze file using existing pipeline
            result = self.analyze_file(file_path)
            
            # Store result if analysis succeeded
            if result:
                self.store_result(file_path, result)
            
        except Exception as e:
            logger.error(f"❌ Error processing file {file_path}: {e}")
    
    def should_analyze(self, file_path):
        """Check if file should be analyzed"""
        try:
            # Check extension
            if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
                return False
            
            # Check if file exists and is readable
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size < MIN_FILE_SIZE or file_size > MAX_FILE_SIZE:
                return False
            
            return True
            
        except Exception:
            return False
    
    def analyze_file(self, file_path):
        """Analyze file using existing 3-stage pipeline with proper decision logic"""
        try:
            logger.info(f"🔍 Starting analysis for: {file_path}")
            
            # Stage 1: Signature Analysis
            logger.info("Stage 1: Signature Analysis")
            signature_result = self.perform_signature_analysis(str(file_path))
            
            # ========================================
            # RESPECT SIGNATURE DECISION LOGIC
            # ========================================
            
            signature_action = signature_result.get('action', 'proceed_to_static')
            
            if signature_action == 'final_verdict_benign':
                logger.info("✅ Signature analysis: BENIGN verdict - stopping pipeline")
                
                result = {
                    'filename': Path(file_path).name,
                    'signature_analysis': signature_result,
                    'static_analysis': {
                        'performed': False,
                        'status': 'skipped',
                        'reason': 'Signature analysis returned benign verdict'
                    },
                    'dynamic_analysis': {
                        'performed': False,
                        'status': 'skipped', 
                        'reason': 'Signature analysis returned benign verdict'
                    },
                    'final_prediction': 0,  # Benign
                    'decision_stage': 'signature_analysis',
                    'total_execution_time': 0.0
                }
                
                return result
                
            elif signature_action == 'final_verdict_ransomware':
                logger.info("🚨 Signature analysis: RANSOMWARE verdict - stopping pipeline")
                
                result = {
                    'filename': Path(file_path).name,
                    'signature_analysis': signature_result,
                    'static_analysis': {
                        'performed': False,
                        'status': 'skipped',
                        'reason': 'Signature analysis returned ransomware verdict'
                    },
                    'dynamic_analysis': {
                        'performed': False,
                        'status': 'skipped',
                        'reason': 'Signature analysis returned ransomware verdict'
                    },
                    'final_prediction': 1,  # Ransomware
                    'decision_stage': 'signature_analysis', 
                    'total_execution_time': 0.0
                }
                
                return result
            
            # If we reach here, signature returned 'proceed_to_static'
            logger.info("🔄 Signature analysis: UNKNOWN - proceeding to static analysis")
            
            # Stage 2: Static Analysis
            logger.info("Stage 2: Static Analysis")
            static_result = self.perform_static_analysis(str(file_path))
            
            # Check if we need dynamic analysis based on static results
            static_prediction = static_result.get('prediction', 0)
            static_confidence = static_result.get('confidence', 0.5)
            
            need_dynamic = False
            dynamic_skip_reason = ""
            
            if static_prediction == 1:
                # Static detected ransomware - skip dynamic
                dynamic_skip_reason = "Static analysis detected ransomware - dynamic analysis not needed"
                logger.info("🚨 Static analysis: RANSOMWARE detected - skipping dynamic")
            elif static_confidence < 0.7:
                # Low confidence - need dynamic analysis
                need_dynamic = True
                logger.info(f"🔄 Static analysis: Low confidence ({static_confidence:.2f}) - proceeding to dynamic")
            else:
                # High confidence benign - skip dynamic
                dynamic_skip_reason = f"Static analysis: High confidence benign ({static_confidence:.2f}) - dynamic not needed"
                logger.info(f"✅ Static analysis: High confidence benign - skipping dynamic")
            
            # Stage 3: Dynamic Analysis (conditional)
            if need_dynamic:
                logger.info("Stage 3: Dynamic Analysis")
                dynamic_result = self.perform_dynamic_analysis_safe(str(file_path), static_result)
            else:
                logger.info("Stage 3: Dynamic Analysis - SKIPPED")
                dynamic_result = {
                    'performed': False,
                    'status': 'skipped',
                    'reason': dynamic_skip_reason
                }
            
            # Determine final prediction with proper logic
            final_prediction = self.determine_final_prediction(static_result, dynamic_result)
            
            # Determine decision stage
            if dynamic_result.get('performed') and dynamic_result.get('status') == 'completed':
                decision_stage = 'dynamic_analysis'
            else:
                decision_stage = 'static_analysis'
            
            logger.info(f"✅ Analysis complete. Final prediction: {final_prediction}, Decision stage: {decision_stage}")
            
            result = {
                'filename': Path(file_path).name,
                'signature_analysis': signature_result,
                'static_analysis': static_result,
                'dynamic_analysis': dynamic_result,
                'final_prediction': final_prediction,
                'decision_stage': decision_stage,
                'total_execution_time': 0.0
            }
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Critical analysis error: {e}")
            return None
        
    def perform_signature_analysis(self, file_path):
        """Perform signature analysis with error handling"""
        try:
            from utils.virustotal_check import analyze_file_signature
            return analyze_file_signature(file_path, 'BALANCED')
        except Exception as e:
            logger.error(f"Signature analysis failed: {e}")
            return {
                'performed': False,
                'error': str(e),
                'decision': 'error',
                'action': 'proceed_to_static'
            }
    
    def perform_static_analysis(self, file_path):
        """FIXED: Perform static analysis with proper feature mapping"""
        try:
            if not self.detector or not self.detector.is_loaded:
                return {'performed': False, 'error': 'Static detector not available'}
            
            from utils.static_feature_extractor import extract_pe_features
            # FIXED: Use the feature mapping path from app config
            features, error = extract_pe_features(file_path, self.static_feature_mapping)
            
            if error:
                return {'performed': False, 'error': error}
            
            static_result = self.detector.predict_ensemble_with_explanation(features)
            static_result['performed'] = True
            return static_result
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            return {
                'performed': False,
                'error': str(e),
                'prediction': 0,
                'confidence': 0.5
            }
    
    def perform_dynamic_analysis_safe(self, file_path, static_result):
        """ENHANCED: Perform dynamic analysis with error isolation to prevent app crashes"""
        dynamic_result = {
            'performed': False,
            'status': 'not_performed',
            'reason': 'Unknown',
            'prediction': None,
            'confidence': None,
            'execution_time': 0.0
        }
        
        try:
            # Check if dynamic analysis should be performed
            if not self.should_perform_dynamic_analysis(static_result):
                dynamic_result.update({
                    'reason': 'Static analysis result was conclusive',
                    'status': 'skipped'
                })
                return dynamic_result
            
            # Check if dynamic detector is available
            if not self.dynamic_detector or not hasattr(self.dynamic_detector, 'is_loaded') or not self.dynamic_detector.is_loaded:
                dynamic_result.update({
                    'reason': 'Dynamic detector not available',
                    'status': 'unavailable'
                })
                return dynamic_result
            
            logger.info("🔍 Starting Cuckoo sandbox analysis...")
            dynamic_start = time.time()
            
            # CRITICAL: Wrap Cuckoo analysis in try-catch to prevent app crashes
            try:
                from utils.cuckoo_client import analyze_file_with_cuckoo
                cuckoo_report = analyze_file_with_cuckoo(file_path)
                
                if cuckoo_report:
                    logger.info("✅ Cuckoo analysis complete, processing results...")
                    prediction_result = self.dynamic_detector.predict_from_cuckoo_report(cuckoo_report)
                    
                    dynamic_result.update({
                        'performed': True,
                        'status': 'completed',
                        'reason': 'Dynamic analysis completed successfully',
                        'prediction': 1 if prediction_result.get('prediction') == 'ransomware' else 0,
                        'prediction_label': prediction_result.get('prediction', 'unknown'),
                        'confidence': prediction_result.get('confidence', 0.5),
                        'execution_time': time.time() - dynamic_start
                    })
                else:
                    dynamic_result.update({
                        'status': 'failed',
                        'reason': 'Cuckoo sandbox analysis failed',
                        'execution_time': time.time() - dynamic_start
                    })
                    
            except Exception as cuckoo_error:
                # CRITICAL: Isolate Cuckoo errors to prevent app crashes
                logger.error(f"🚨 Cuckoo analysis error (ISOLATED): {cuckoo_error}")
                dynamic_result.update({
                    'status': 'error',
                    'reason': f'Cuckoo analysis error: {str(cuckoo_error)}',
                    'execution_time': time.time() - dynamic_start,
                    'error_isolated': True  # Flag that error was caught and isolated
                })
                
        except Exception as dynamic_error:
            # CRITICAL: Isolate all dynamic analysis errors
            logger.error(f"🚨 Dynamic analysis error (ISOLATED): {dynamic_error}")
            dynamic_result.update({
                'status': 'error',
                'reason': f'Dynamic analysis error: {str(dynamic_error)}',
                'error_isolated': True
            })
        
        return dynamic_result
    
    def should_perform_dynamic_analysis(self, static_result):
        """Determine if dynamic analysis should be performed"""
        # Skip if static analysis failed
        if not static_result.get('performed', False):
            return False
        
        # Skip if static analysis detected ransomware with high confidence
        static_prediction = static_result.get('prediction', 0)
        static_confidence = static_result.get('confidence', 0.0)
        
        if static_prediction == 1 and static_confidence > 0.8:
            return False  # High confidence ransomware detection
        
        # Perform dynamic analysis for benign or low-confidence results
        return True
    
    def determine_final_prediction(self, static_result, dynamic_result):
        """Determine final prediction from analysis stages"""
        # Priority: Dynamic > Static
        
        # If dynamic analysis completed successfully, use its result
        if dynamic_result.get('performed') and dynamic_result.get('status') == 'completed':
            return dynamic_result.get('prediction', 0)
        
        # Fall back to static analysis
        if static_result.get('performed'):
            return static_result.get('prediction', 0)
        
        # Default to benign if all analyses failed
        return 0
    
    def store_result(self, file_path, result):
        """Store analysis result in database"""
        try:
            if not db:
                logger.warning("Database not available for storing result")
                return

            file_hash = None
            
            try:
                file_hash = calculate_file_hash(str(file_path))
            except Exception as e:
                logger.warning(f"Could not calculate file info: {e}")
            
            db.store_result(
                filename=result['filename'],
                file_hash=file_hash,
                source="auto",
                prediction=result.get('final_prediction', 0),
                analysis_result=result
            )
            
            logger.info(f"✅ Analysis result stored in database for {result['filename']}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis result: {e}")

def start_monitoring(app_instance=None):
    """FIXED: Start file system monitoring with proper feature mapping"""
    global observer, monitoring_active, db
    
    if monitoring_active:
        logger.warning("Monitoring already active")
        return
    
    try:
        # Initialize database
        db = DetectionDatabase()
        
        # Get detector instances from app instance
        if not app_instance:
            logger.error("No app instance provided to start monitoring")
            return

        detector = app_instance.detector
        dynamic_detector = app_instance.dynamic_detector
        
        if not detector:
            logger.error("Static detector not available - monitoring disabled")
            return
        
        # FIXED: Get the static feature mapping from app config
        static_feature_mapping = app_instance.config.get('STATIC_FEATURE_MAPPING')
        
        # Create event handler WITH feature mapping
        event_handler = RansomwareFileHandler(
            detector, 
            dynamic_detector, 
            static_feature_mapping  # Pass feature mapping path
        )
        
        # Create observer
        observer = Observer()
        
        # Add monitoring paths
        monitored_count = 0
        for path in MONITORED_PATHS:
            expanded_path = os.path.expandvars(path)
            
            if os.path.exists(expanded_path):
                observer.schedule(event_handler, expanded_path, recursive=True)
                monitored_count += 1
                logger.info(f"📁 Monitoring: {expanded_path}")
            else:
                logger.warning(f"⚠️  Path not found: {expanded_path}")
        
        if monitored_count > 0:
            observer.start()
            monitoring_active = True
            logger.info(f"🚀 File monitoring started - watching {monitored_count} directories")
            logger.info("🔧 Using proper feature mapping for static analysis")
            logger.info("🛡️  Error isolation enabled for Cuckoo analysis")
        else:
            logger.error("❌ No valid paths to monitor")
            
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")

def stop_monitoring():
    """Stop file system monitoring"""
    global observer, monitoring_active
    
    if observer and monitoring_active:
        observer.stop()
        observer.join()
        monitoring_active = False
        logger.info("🛑 File monitoring stopped")

def is_monitoring_active():
    """Check if monitoring is currently active"""
    return monitoring_active

def get_monitoring_status():
    """Get current monitoring status"""
    return {
        'active': monitoring_active,
        'monitored_paths': MONITORED_PATHS,
        'allowed_extensions': list(ALLOWED_EXTENSIONS),
        'feature_mapping_fix': True,
        'error_isolation': True
    }