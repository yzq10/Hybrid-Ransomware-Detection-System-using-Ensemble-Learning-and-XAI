import os
import logging
import threading
from flask import Flask
from flask_cors import CORS

# Import route blueprints
from routes.api import api_bp
from routes.main import main_bp
from utils.file_monitor import start_monitoring

# Configure logging FIRST
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# THEN set specific loggers
logging.getLogger('ransomware_detector').setLevel(logging.WARNING)
logging.getLogger('dynamic_detector').setLevel(logging.WARNING)
logging.getLogger('utils').setLevel(logging.WARNING)

# Import your ransomware detector
from ransomware_detector import RansomwareDetector
from dynamic_detector import DynamicDetector  # ← UPDATED: Use clean brain


def create_app():
    """Application factory function"""
    # Initialize Flask app
    app = Flask(__name__)
    CORS(app)  # Enable CORS for all routes

    # Configuration
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1 GB max upload size
    app.config['ALLOWED_EXTENSIONS'] = {'exe', 'dll', 'sys'}
    app.config['VT_API_KEY'] = os.environ.get('VT_API_KEY', 'your_vt_api_key_here')
    app.config['VT_SECURITY_MODE'] = os.environ.get('VT_SECURITY_MODE', 'BALANCED')
    
    # Static model paths
    app.config['STATIC_ENSEMBLE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models', 'static_ensemble')
    app.config['STATIC_FEATURE_MAPPING'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models', 'static_ensemble', 'feature_names.json')

    # Dynamic model paths - UPDATED for clean system
    app.config['DYNAMIC_ENSEMBLE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models', 'dynamic_ensemble')
    app.config['DYNAMIC_FEATURE_MAPPING'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models', 'RFE_selected_feature_names_dic.json')

    # Add Cuckoo sandbox configuration
    app.config['CUCKOO_API_URL'] = os.environ.get('CUCKOO_API_URL', 'http://192.168.11.145:8090')
    app.config['CUCKOO_TIMEOUT'] = int(os.environ.get('CUCKOO_TIMEOUT', '1200')) 

    # Create necessary folders
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.dirname(app.config['STATIC_ENSEMBLE_DIR']), exist_ok=True)

    # ========================================
    # Static Ensemble Detector Initialization
    # ========================================
    
    print("="*60)
    print("INITIALIZING STATIC RANSOMWARE DETECTOR")
    print("="*60)

    # Check if static ensemble model files exist
    static_files_exist = True
    static_required_files = [
        ('XGBoost Model', os.path.join(app.config['STATIC_ENSEMBLE_DIR'], 'xgboost_model.pkl')),
        ('SVM Model', os.path.join(app.config['STATIC_ENSEMBLE_DIR'], 'svm_model.pkl')),
        ('Random Forest Model', os.path.join(app.config['STATIC_ENSEMBLE_DIR'], 'randomforest_model.pkl')),
        ('SVM Scaler', os.path.join(app.config['STATIC_ENSEMBLE_DIR'], 'svm_scaler.pkl')),
        ('Feature Names', app.config['STATIC_FEATURE_MAPPING'])
    ]

    print("\nChecking required static ensemble files:")
    for file_type, file_path in static_required_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"  ✓ {file_type}: Found ({file_size:,} bytes)")
        else:
            print(f"  ✗ {file_type}: MISSING")
            static_files_exist = False

    # Initialize static detector
    if static_files_exist:
        print("\nLoading static ensemble detector...")
        try:
            detector = RansomwareDetector()
            model_loaded = detector.load_ensemble_models(app.config['STATIC_ENSEMBLE_DIR'])
            
            # Check if loading was successful
            if model_loaded and detector.is_loaded:
                # model_info = detector.get_model_info()
                print(f"  ✓ Models loaded: {list(detector.ensemble_models.keys())}")
                print(f"  ✓ Feature count: {len(detector.features) if hasattr(detector, 'features') else 'Unknown'}")
                
                # Initialize XAI explainer
                print(f"  ✓ Initializing static XAI explainer...")
                try:
                    detector.initialize_static_xai_explainer(background_data=None)
                    if detector.xai_explainer and detector.xai_explainer.is_loaded:
                        print(f"  ✓ XAI explainer: Available")
                    else:
                        print(f"  ⚠️  XAI explainer: Incomplete initialization")
                except Exception as e:
                    print(f"  ✗ XAI explainer initialization failed: {e}")
                
                print("\n🎯 STATIC ENSEMBLE DETECTOR: READY")
                print("System will perform static PE analysis with explanations")
                app.detector = detector
            else:
                print("  ✗ Static ensemble detector failed to load")
                app.detector = None
                
        except Exception as e:
            print(f"  ✗ Static detector loading failed: {str(e)}")
            print("  System will run without static analysis")
            app.detector = None
    else:
        print("\n" + "⚠"*3 + " WARNING " + "⚠"*3)
        print("Cannot initialize static detector - required files missing!")
        print("System will run without static analysis")
        app.detector = None

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    # ========================================
    # UPDATED: Clean Dynamic Detector Initialization
    # ========================================

    print("\n" + "="*60)
    print("INITIALIZING CLEAN DYNAMIC RANSOMWARE DETECTOR")
    print("="*60)

    # Check if ensemble model files exist
    ensemble_files_exist = True
    required_files = [
        ('XGBoost Model', os.path.join(app.config['DYNAMIC_ENSEMBLE_DIR'], 'xgboost_model.pkl')),
        ('Random Forest Model', os.path.join(app.config['DYNAMIC_ENSEMBLE_DIR'], 'randomforest_model.pkl')),
        ('SVM Model', os.path.join(app.config['DYNAMIC_ENSEMBLE_DIR'], 'svm_model.pkl')),
        ('SVM Scaler', os.path.join(app.config['DYNAMIC_ENSEMBLE_DIR'], 'svm_scaler.pkl')),
        ('Feature Mapping', app.config['DYNAMIC_FEATURE_MAPPING'])
    ]

    print("\nChecking required ensemble files:")
    for file_type, file_path in required_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"  ✓ {file_type}: Found ({file_size:,} bytes)")
        else:
            print(f"  ✗ {file_type}: MISSING")
            ensemble_files_exist = False

    # Initialize clean dynamic detector
    if ensemble_files_exist:
        print("\nLoading clean dynamic detector...")
        try:
            # UPDATED: Use clean brain with simple loading
            dynamic_detector = DynamicDetector()
            dynamic_detector.load_models(
                app.config['DYNAMIC_ENSEMBLE_DIR'], 
                app.config['DYNAMIC_FEATURE_MAPPING']
            )
            
            # Check if loading was successful
            if dynamic_detector.is_loaded:
                model_info = dynamic_detector.get_model_info()
                print(f"  ✓ Models loaded: {model_info.get('models', [])}")
                print(f"  ✓ XAI explainer: {'Available' if model_info.get('xai_available') else 'Not available'}")
                print(f"  ✓ Feature count: {model_info.get('feature_count', 'Unknown')}")
                print("\n🎯 CLEAN DYNAMIC DETECTOR: READY")
                print("System will perform FULL 3-STAGE analysis with explanations")
                app.dynamic_detector = dynamic_detector
            else:
                print("  ✗ Clean dynamic detector failed to load")
                app.dynamic_detector = None
                
        except Exception as e:
            print(f"  ✗ Clean dynamic detector loading failed: {str(e)}")
            print("  System will run in STATIC-ONLY mode")
            app.dynamic_detector = None
    else:
        print("\n" + "⚠"*3 + " WARNING " + "⚠"*3)
        print("Cannot initialize dynamic detector - required files missing!")
        print("System will run in STATIC-ONLY mode")
        app.dynamic_detector = None

    print("="*60)
    
    # NEW: Start file monitoring with app context
    def start_monitoring_with_context():
        start_monitoring(app_instance=app)  # Pass app instance directly

    monitor_thread = threading.Thread(target=start_monitoring_with_context, daemon=True)
    monitor_thread.start()
    print("\n🔍 File monitoring started in background")
    
    return app

if __name__ == '__main__':
    print("\n" + "="*60)
    print("3-STAGE RANSOMWARE DETECTION SYSTEM")
    print("="*60)
    
    app = create_app()
    
    # Suppress Flask development server warning
    cli = logging.getLogger('werkzeug')
    cli.setLevel(logging.ERROR)
    
    print("\n🚀 SERVER STATUS:")
    print("  • Host: 0.0.0.0 (All interfaces)")
    print("  • Port: 5000")
    print("  • Local: http://127.0.0.1:5000")
    print("  • Network: http://192.168.100.11:5000")
    print("\n📝 LOGS: Only warnings and errors will be shown")
    print("🛑 Press CTRL+C to quit")
    print("="*60 + "\n")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)