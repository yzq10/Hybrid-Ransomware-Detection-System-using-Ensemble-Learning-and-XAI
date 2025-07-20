import os
import time
import threading
import shutil
import tempfile
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import psutil

from .database import DetectionDatabase, calculate_file_hash

logger = logging.getLogger(__name__)

# Configuration
MONITORED_PATHS = [
    r"C:\Users\Yap Zhan Quan\Downloads"
]

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys'}
MIN_FILE_SIZE = 1024  # 1KB minimum
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB maximum

# Enhanced timing configuration
INITIAL_WAIT = 3  # Initial wait after file creation
STABILITY_CHECK_INTERVAL = 2  # Check file stability every 2 seconds
MAX_STABILITY_CHECKS = 10  # Maximum number of stability checks
FILE_HANDLE_CHECK_TIMEOUT = 30  # Maximum time to wait for file handle release

# Global variables
observer = None
monitoring_active = False
db = None

class FileHandleManager:
    """Utility class for managing Windows file handles safely"""
    
    @staticmethod
    def is_file_locked(file_path):
        """Check if file is locked by another process"""
        try:
            # Try to open file for exclusive access
            with open(file_path, 'r+b') as f:
                # Try to read a byte to ensure file is accessible
                f.seek(0)
                f.read(1)
            return False
        except (IOError, OSError, PermissionError):
            return True
    
    @staticmethod
    def wait_for_file_release(file_path, timeout=FILE_HANDLE_CHECK_TIMEOUT):
        """Wait for file to be released by all processes"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if not FileHandleManager.is_file_locked(file_path):
                return True
            
            logger.debug(f"File still locked, waiting... {file_path}")
            time.sleep(1)
        
        logger.warning(f"File remained locked after {timeout}s timeout: {file_path}")
        return False
    
    @staticmethod
    def is_file_stable(file_path, check_duration=4):
        """Check if file size is stable (not being written to)"""
        try:
            initial_size = os.path.getsize(file_path)
            initial_mtime = os.path.getmtime(file_path)
            
            time.sleep(check_duration)
            
            final_size = os.path.getsize(file_path)
            final_mtime = os.path.getmtime(file_path)
            
            return (initial_size == final_size and initial_mtime == final_mtime)
        except (OSError, IOError):
            return False
    
    @staticmethod
    def get_file_processes(file_path):
        """Get list of processes that have the file open"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    open_files = proc.info['open_files']
                    if open_files:
                        for file_info in open_files:
                            if file_info.path.lower() == file_path.lower():
                                processes.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Could not enumerate file processes: {e}")
        
        return processes
    
    @staticmethod
    def create_safe_copy(source_path, temp_dir=None):
        """Create a safe copy of file for analysis"""
        try:
            if temp_dir is None:
                temp_dir = tempfile.gettempdir()
            
            file_name = os.path.basename(source_path)
            timestamp = int(time.time())
            safe_name = f"monitor_{timestamp}_{file_name}"
            temp_path = os.path.join(temp_dir, safe_name)
            
            # Use shutil.copy2 to preserve metadata
            shutil.copy2(source_path, temp_path)
            
            # Verify copy was successful
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                logger.info(f"Safe copy created: {temp_path}")
                return temp_path
            else:
                logger.error(f"Failed to create safe copy: {temp_path}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating safe copy: {e}")
            return None

class RansomwareFileHandler(FileSystemEventHandler):
    """Enhanced file handler with proper handle management"""
    
    def __init__(self, detector, dynamic_detector, static_feature_mapping=None):
        self.detector = detector
        self.dynamic_detector = dynamic_detector
        self.static_feature_mapping = static_feature_mapping  # Store feature mapping path
        self.processing_files = set()  # Track files being processed
        self.handle_manager = FileHandleManager()
        
    def on_created(self, event):
        """Called when a new file is created"""
        if not event.is_directory:
            self.process_file(event.src_path)
    
    def on_moved(self, event):
        """Called when a file is moved/renamed"""
        if not event.is_directory:
            self.process_file(event.dest_path)
    
    def process_file(self, file_path):
        """Enhanced file processing with proper handle management"""
        try:
            file_path = Path(file_path)
            file_path_str = str(file_path)
            
            # Prevent duplicate processing
            if file_path_str in self.processing_files:
                logger.debug(f"File already being processed: {file_path}")
                return
            
            # Check if file should be analyzed
            if not self.should_analyze(file_path):
                return
            
            self.processing_files.add(file_path_str)
            logger.info(f"🔍 Auto-detected file: {file_path}")
            
            try:
                # STEP 1: Initial wait for file creation to complete
                logger.debug(f"Initial wait ({INITIAL_WAIT}s) for file creation completion...")
                time.sleep(INITIAL_WAIT)
                
                # STEP 2: Wait for file stability (size/modification time)
                logger.debug("Checking file stability...")
                if not self.wait_for_file_stability(file_path):
                    logger.warning(f"File unstable, skipping: {file_path}")
                    return
                
                # STEP 3: Wait for file handle release
                logger.debug("Waiting for file handle release...")
                if not self.handle_manager.wait_for_file_release(file_path_str):
                    logger.warning(f"File still locked, skipping: {file_path}")
                    return
                
                # STEP 4: Final validation
                if not self.final_file_validation(file_path):
                    logger.warning(f"Final validation failed, skipping: {file_path}")
                    return
                
                # STEP 5: Create safe copy for analysis
                logger.debug("Creating safe copy for analysis...")
                safe_copy_path = self.handle_manager.create_safe_copy(file_path_str)
                if not safe_copy_path:
                    logger.error(f"Failed to create safe copy, skipping: {file_path}")
                    return
                
                logger.info(f"✅ File ready for analysis: {file_path}")
                
                # STEP 6: Perform analysis on safe copy
                result = self.analyze_file_safe(safe_copy_path, file_path.name)
                
                # STEP 7: Store result if analysis succeeded
                if result:
                    self.store_analysis_result(file_path_str, result)
                
                # STEP 8: Cleanup safe copy
                try:
                    os.remove(safe_copy_path)
                    logger.debug(f"Cleaned up safe copy: {safe_copy_path}")
                except Exception as cleanup_error:
                    logger.warning(f"Could not cleanup safe copy: {cleanup_error}")
                
            except Exception as process_error:
                logger.error(f"Error in file processing: {process_error}")
                
        except Exception as outer_error:
            logger.error(f"Critical error processing file {file_path}: {outer_error}")
        finally:
            # Always remove from processing set
            if file_path_str in self.processing_files:
                self.processing_files.remove(file_path_str)
    
    def wait_for_file_stability(self, file_path, max_checks=MAX_STABILITY_CHECKS):
        """Wait for file to become stable (not being written to)"""
        for attempt in range(max_checks):
            logger.debug(f"Stability check {attempt + 1}/{max_checks}")
            
            if self.handle_manager.is_file_stable(file_path, STABILITY_CHECK_INTERVAL):
                logger.debug("File is stable")
                return True
            
            logger.debug("File still changing, waiting...")
            
            # Check if file still exists
            if not file_path.exists():
                logger.warning(f"File disappeared during stability check: {file_path}")
                return False
        
        logger.warning(f"File never stabilized after {max_checks} checks: {file_path}")
        return False
    
    def final_file_validation(self, file_path):
        """Final validation before analysis"""
        try:
            # Check file still exists
            if not file_path.exists():
                logger.debug("File no longer exists")
                return False
            
            # Check file size within limits
            file_size = file_path.stat().st_size
            if file_size < MIN_FILE_SIZE or file_size > MAX_FILE_SIZE:
                logger.debug(f"File size outside limits: {file_size}")
                return False
            
            # Test read access
            try:
                with open(file_path, 'rb') as test_file:
                    test_file.read(1024)  # Try to read first 1KB
                return True
            except (PermissionError, IOError) as e:
                logger.debug(f"File access test failed: {e}")
                return False
                
        except Exception as e:
            logger.debug(f"Final validation error: {e}")
            return False
    
    def should_analyze(self, file_path):
        """Check if file should be analyzed"""
        try:
            # Check extension
            if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
                return False
            
            # Check if file exists and is readable
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Basic size check
            try:
                file_size = file_path.stat().st_size
                if file_size < MIN_FILE_SIZE or file_size > MAX_FILE_SIZE:
                    return False
            except OSError:
                return False
            
            return True
            
        except Exception:
            return False
    
    def analyze_file_safe(self, safe_file_path, original_filename):
        """Analyze file using existing 3-stage pipeline with error isolation"""
        try:
            logger.info(f"🔍 Starting safe analysis for: {original_filename}")
            analysis_start_time = time.time()
            
            # Stage 1: Signature Analysis
            logger.debug("Stage 1: Signature Analysis")
            signature_result = self.perform_signature_analysis(safe_file_path)
            
            # Stage 2: Static Analysis
            logger.debug("Stage 2: Static Analysis")
            static_result = self.perform_static_analysis(safe_file_path)
            
            # Stage 3: Dynamic Analysis (with enhanced error handling)
            logger.debug("Stage 3: Dynamic Analysis")
            dynamic_result = self.perform_dynamic_analysis_safe(safe_file_path, static_result)
            
            # Determine final prediction
            final_prediction = self.determine_final_prediction(
                signature_result, static_result, dynamic_result
            )
            
            total_time = time.time() - analysis_start_time
            
            result = {
                'filename': original_filename,
                'signature_analysis': signature_result,
                'static_analysis': static_result,
                'dynamic_analysis': dynamic_result,
                'final_prediction': final_prediction,
                'total_execution_time': total_time,
                'analysis_mode': 'auto_monitoring',
                'source': 'auto'
            }
            
            logger.info(f"✅ Analysis complete for {original_filename}. Final prediction: {final_prediction}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Analysis failed for {original_filename}: {e}")
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
        """Perform static analysis with error handling"""
        try:
            if not self.detector or not self.detector.is_loaded:
                return {'performed': False, 'error': 'Static detector not available'}
            
            from utils.static_feature_extractor import extract_pe_features
            features, error = extract_pe_features(file_path, self.static_feature_mapping)  # Use the feature mapping
            
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
        """Perform dynamic analysis with enhanced error isolation"""
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
            
            # ISOLATION: Wrap Cuckoo analysis in try-catch to prevent app crashes
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
    
    def determine_final_prediction(self, signature_result, static_result, dynamic_result):
        """Determine final prediction from all analysis stages"""
        # Priority: Dynamic > Static > Signature
        
        # If dynamic analysis completed successfully, use its result
        if dynamic_result.get('performed') and dynamic_result.get('status') == 'completed':
            return dynamic_result.get('prediction', 0)
        
        # Fall back to static analysis
        if static_result.get('performed'):
            return static_result.get('prediction', 0)
        
        # Fall back to signature analysis
        if signature_result.get('decision') == 'ransomware':
            return 1
        elif signature_result.get('decision') == 'benign':
            return 0
        
        # Default to benign if all analyses failed
        return 0
    
    def store_analysis_result(self, file_path, result):
        """Store analysis result in database"""
        try:
            if not db:
                logger.warning("Database not available for storing result")
                return
            
            file_size = 0
            file_hash = None
            
            try:
                file_size = os.path.getsize(file_path)
                file_hash = calculate_file_hash(file_path)
            except Exception as e:
                logger.warning(f"Could not calculate file info: {e}")
            
            db.store_result(
                filename=result['filename'],
                file_size=file_size,
                file_hash=file_hash,
                source="auto",
                prediction=result.get('final_prediction', 0),
                analysis_result=result
            )
            
            logger.info(f"✅ Analysis result stored in database for {result['filename']}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis result: {e}")

def start_monitoring(app_instance=None):
    """Start file system monitoring with enhanced error handling"""
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
        
        # Create enhanced event handler
        event_handler = RansomwareFileHandler(
            detector, 
            dynamic_detector, 
            app_instance.config.get('STATIC_FEATURE_MAPPING')  # Pass the feature mapping path
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
            logger.info(f"🚀 Enhanced file monitoring started - watching {monitored_count} directories")
            logger.info("🔒 File handle management enabled")
            logger.info("🛡️  Error isolation enabled")
        else:
            logger.error("❌ No valid paths to monitor")
            
    except Exception as e:
        logger.error(f"Failed to start enhanced monitoring: {e}")

def stop_monitoring():
    """Stop file system monitoring"""
    global observer, monitoring_active
    
    if observer and monitoring_active:
        observer.stop()
        observer.join()
        monitoring_active = False
        logger.info("🛑 Enhanced file monitoring stopped")

def is_monitoring_active():
    """Check if monitoring is currently active"""
    return monitoring_active

def get_monitoring_status():
    """Get current monitoring status"""
    return {
        'active': monitoring_active,
        'monitored_paths': MONITORED_PATHS,
        'allowed_extensions': list(ALLOWED_EXTENSIONS),
        'file_handle_management': True,
        'error_isolation': True,
        'enhanced_features': [
            'File stability checking',
            'Handle release waiting',
            'Safe file copying',
            'Cuckoo error isolation',
            'Process tracking'
        ]
    }