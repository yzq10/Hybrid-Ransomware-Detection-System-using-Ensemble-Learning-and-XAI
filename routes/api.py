import os
import time
import uuid
import logging
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

# Import utilities
from utils.static_feature_extractor import extract_pe_features
from utils.file_handler import allowed_file, save_uploaded_file, cleanup_file, validate_file_upload
from utils.cuckoo_client import analyze_file_with_cuckoo, CuckooAnalysisError
from utils.virustotal_check import analyze_file_signature
from utils.database import DetectionDatabase, calculate_file_hash

db = DetectionDatabase()

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
api_bp = Blueprint('api', __name__)

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint - Fixed to properly detect loaded models"""
    detector = current_app.detector
    dynamic_detector = current_app.dynamic_detector
    
    # Check static ensemble status
    static_ensemble_loaded = (
        detector is not None and 
        hasattr(detector, 'is_loaded') and 
        detector.is_loaded and
        hasattr(detector, 'ensemble_models') and
        len(detector.ensemble_models) >= 3
    )
    
    # Check dynamic model status  
    dynamic_status = 'not_available'
    dynamic_model_loaded = False
    
    if dynamic_detector is not None:
        if hasattr(dynamic_detector, 'is_loaded') and dynamic_detector.is_loaded:
            dynamic_status = 'loaded'
            dynamic_model_loaded = True
        else:
            dynamic_status = 'failed_to_load'
    
    # Overall system status
    if not static_ensemble_loaded:
        overall_status = 'error'
        status_code = 503
    elif not dynamic_model_loaded:
        overall_status = 'partial'  # Static only
        status_code = 200
    else:
        overall_status = 'ok'  # Full system
        status_code = 200
    
    response_data = {
        'status': overall_status,
        'static_ensemble_loaded': static_ensemble_loaded,
        'static_model_count': len(detector.ensemble_models) if static_ensemble_loaded else 0,
        'static_models': list(detector.ensemble_models.keys()) if static_ensemble_loaded else [],
        'dynamic_model_status': dynamic_status,
        'dynamic_model_loaded': dynamic_model_loaded,
        'system_mode': 'full_3_stage' if dynamic_model_loaded else 'static_only',
        'message': 'All systems operational' if overall_status == 'ok' else 
                  'Static ensemble only' if overall_status == 'partial' else 
                  'System not ready'
    }
    
    return jsonify(response_data), status_code

@api_bp.route('/model/info', methods=['GET'])
def model_info():
    """Get comprehensive information about all loaded models (UPDATED: includes dynamic capabilities)"""
    detector = current_app.detector
    dynamic_detector = current_app.dynamic_detector
    
    if detector.model is None:
        return jsonify({
            'status': 'error',
            'message': 'Static model not loaded'
        }), 404
    
    try:
        response_data = {
            'status': 'success',
            'static_model': detector.get_model_info(),
            'dynamic_model': None
        }
        
        # Add static model feature importance if available
        if hasattr(detector.model, 'feature_importances_'):
            importances = detector.model.feature_importances_
            feature_importance = {detector.features[i]: float(importance) 
                               for i, importance in enumerate(importances)}
            
            # Sort by importance
            sorted_importance = dict(sorted(feature_importance.items(), 
                                         key=lambda item: item[1], 
                                         reverse=True))
            
            response_data['static_model']['feature_importance'] = sorted_importance
        
        # UPDATED: Add comprehensive dynamic model info (merged from /dynamic-status)
        if dynamic_detector is not None and hasattr(dynamic_detector, 'is_loaded') and dynamic_detector.is_loaded:
            try:
                try:
                    dynamic_info = dynamic_detector.get_model_info()
                    if callable(dynamic_info):  # Check if it's a function
                        dynamic_info = {'status': 'error', 'error': 'get_model_info returned function instead of data'}
                except AttributeError:
                    dynamic_info = {'status': 'error', 'error': 'get_model_info method not found'}
                except Exception as e:
                    dynamic_info = {'status': 'error', 'error': str(e)}
                
                # Enhanced dynamic info with capabilities
                has_ensemble = hasattr(dynamic_detector, 'models') and bool(dynamic_detector.models)
                has_xai = dynamic_detector.xai_explainer is not None
                xai_loaded = (has_xai and 
                             hasattr(dynamic_detector.xai_explainer, 'is_loaded') and 
                             dynamic_detector.xai_explainer.is_loaded) if has_xai else False
                
                response_data['dynamic_model'] = {
                    **dynamic_info,
                    'ensemble_available': has_ensemble,
                    'analysis_type': 'ensemble' if has_ensemble else 'single_model',
                    'xai_available': has_xai,
                    'xai_loaded': xai_loaded,
                    'capabilities': {
                        'behavioral_analysis': True,
                        'ensemble_voting': has_ensemble,
                        'explainable_ai': xai_loaded,
                        'cuckoo_integration': True
                    }
                }
                
                # Add individual model details if ensemble
                if has_ensemble:
                    model_details = {}
                    for model_name in dynamic_detector.models.keys():
                        model = dynamic_detector.models[model_name]
                        model_details[model_name] = {
                            'type': type(model).__name__,
                            'loaded': True
                        }
                    response_data['dynamic_model']['individual_models'] = model_details
                
            except Exception as e:
                response_data['dynamic_model'] = {
                    'status': 'error',
                    'error': str(e)
                }
        else:
            response_data['dynamic_model'] = {
                'status': 'not_available',
                'reason': 'Dynamic detector not loaded',
                'ensemble_available': False,
                'analysis_type': 'none',
                'xai_available': False,
                'xai_loaded': False,
                'capabilities': {
                    'behavioral_analysis': False,
                    'ensemble_voting': False,
                    'explainable_ai': False,
                    'cuckoo_integration': False
                }
            }
        
        # Add Cuckoo sandbox status check
        try:
            from utils.cuckoo_client import CuckooClient
            client = CuckooClient()
            is_connected = client.test_connection()
            
            response_data['cuckoo_status'] = {  # ← Fixed variable name
                'status': 'connected' if is_connected else 'disconnected',
                'connected': is_connected,
                'api_url': client.base_url,
                'message': 'Cuckoo Sandbox is accessible' if is_connected else 'Cannot connect to Cuckoo Sandbox'
            }
        except Exception as e:
            response_data['cuckoo_status'] = {  # ← Fixed variable name
                'status': 'error',
                'connected': False,
                'message': f'Cuckoo status check failed: {str(e)}',
                'error': str(e)
            }

        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error getting model info: {str(e)}'
        }), 500

@api_bp.route('/scan', methods=['POST'])
def scan_file():
    """Endpoint to scan a file for ransomware using 3-stage analysis: Signature → Static → Dynamic"""
    detector = current_app.detector
    dynamic_detector = current_app.dynamic_detector
    
    # Check if static model is loaded
    if not detector.is_loaded:
        return jsonify({
            'status': 'error',
            'message': 'Static ensemble not initialized'
        }), 503
    
    # Determine system capabilities
    dynamic_available = (
        dynamic_detector is not None and 
        hasattr(dynamic_detector, 'is_loaded') and 
        dynamic_detector.is_loaded
    )
    
    has_ensemble = dynamic_available and hasattr(dynamic_detector, 'models') and bool(dynamic_detector.models)
    
    logger.info(f"Full 3-stage pipeline available: Signature → Static → {'Dynamic Ensemble' if has_ensemble else 'Dynamic Single' if dynamic_available else 'No Dynamic'}")
    
    # File validation
    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file provided'
        }), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected'
        }), 400

    if not allowed_file(file.filename, current_app.config['ALLOWED_EXTENSIONS']):
        return jsonify({
            'status': 'error',
            'message': f'File type not allowed. Allowed types: {", ".join(current_app.config["ALLOWED_EXTENSIONS"])}'
        }), 400

    try:
        # Save the file
        file_path = save_uploaded_file(file, current_app.config['UPLOAD_FOLDER'])
        logger.info(f"File saved: {file_path}")
        
        # Start timing
        import time
        start_time = time.time()
        
        # ========================================
        # STAGE 1: SIGNATURE ANALYSIS (VirusTotal)
        # ========================================

        logger.info("STAGE 1: Starting signature analysis...")
        from utils.virustotal_check import analyze_file_signature

        signature_start = time.time()
        signature_result = analyze_file_signature(file_path, current_app.config.get('VT_SECURITY_MODE', 'BALANCED'))
        signature_analysis_time = time.time() - signature_start

        # Handle signature analysis results - ONLY STOP IF RANSOMWARE DETECTED
        if signature_result['action'] == 'final_verdict_ransomware':
            
            # FIXED: Proper result structure for signature-only ransomware result
            result = {
                'status': 'success',
                'filename': file.filename,
                'signature_analysis': {
                    'performed': True,
                    'decision': signature_result['decision'],
                    'confidence': float(signature_result['confidence']),
                    'reason': signature_result['reason'],
                    'action': signature_result['action'],
                    'stage': signature_result['stage'],
                    'file_hash': signature_result.get('file_hash', ''),
                    'ratios': signature_result.get('ratios', {}),
                    'security_mode': signature_result.get('security_mode', 'BALANCED'),
                    'execution_time': signature_analysis_time
                },
                'static_analysis': {
                    'performed': False,
                    'status': 'skipped',
                    'reason': 'Signature analysis detected ransomware',
                    'prediction': 1,
                    'prediction_label': 'Ransomware',
                    'confidence': float(signature_result['confidence']),
                    'probabilities': {
                        'benign': 1.0 - float(signature_result['confidence']),
                        'ransomware': float(signature_result['confidence'])
                    },
                    'ensemble_details': {},
                    'feature_count': 0,
                    'execution_time': 0.0
                },
                'dynamic_analysis': {
                    'performed': False,
                    'status': 'skipped',
                    'reason': 'Signature analysis detected ransomware',
                    'prediction': None,
                    'prediction_label': None,
                    'confidence': None,
                    'probabilities': {
                        'benign': None,
                        'ransomware': None
                    },
                    'analysis_type': None,
                    'execution_time': 0.0
                },
                'final_prediction': 1,
                'final_label': 'Ransomware',
                'prediction_label': 'Ransomware',
                'confidence': float(signature_result['confidence']),
                'analysis_mode': 'signature_only',
                'total_execution_time': time.time() - start_time,
                'decision_stage': 'signature_analysis',
                'decision_reason': signature_result['reason']
            }
            
            # ✅ STORE TO DATABASE BEFORE CLEANUP
            file_hash = calculate_file_hash(file_path)
            db.store_result(
                filename=file.filename,
                file_hash=file_hash,
                source="manual",
                prediction=1,
                analysis_result=result
            )
            
            cleanup_file(file_path)
            return jsonify(result)

        else:
            # Continue to static analysis for BOTH 'benign' and 'unknown' decisions
            logger.info(f"Signature analysis: {signature_result['decision']} - proceeding to static analysis")

        # ========================================
        # STAGE 2: STATIC ANALYSIS (Ensemble ML)
        # ========================================
        
        logger.info("STAGE 2: Starting static ensemble analysis...")
        
        # Extract features using the new ensemble method
        static_start = time.time()
        features, error = extract_pe_features(file_path, current_app.config.get('STATIC_FEATURE_MAPPING'))
        
        if error:
            cleanup_file(file_path)
            return jsonify({
                'status': 'error',
                'message': f'Failed to extract features: {error}'
            }), 400
        
        # Make ensemble prediction
        static_result = detector.predict_ensemble_with_explanation(features, top_k=10)
        static_analysis_time = time.time() - static_start

        # FIXED: Extract static results with proper error handling
        static_prediction = static_result.get('prediction', 0)
        static_confidence = static_result.get('confidence', 0.0)
        static_probabilities = static_result.get('probabilities', {'benign': 0.5, 'ransomware': 0.5})

        # FIXED: Ensure prediction is valid
        if static_prediction is None or (static_prediction != 0 and static_prediction != 1):
            static_prediction = 0  # Default to benign if invalid

        # FIXED: Ensure confidence is valid
        if not isinstance(static_confidence, (int, float)) or static_confidence != static_confidence:  # NaN check
            static_confidence = 0.5

        # FIXED: Ensure probabilities is valid dict
        if not isinstance(static_probabilities, dict) or 'benign' not in static_probabilities or 'ransomware' not in static_probabilities:
            static_probabilities = {'benign': 0.5, 'ransomware': 0.5}

        # Determine if we need dynamic analysis
        need_dynamic = False
        dynamic_reason = ""
        
        if static_prediction == 1:
            # Static detected ransomware - skip dynamic
            dynamic_reason = "Static analysis detected ransomware - dynamic analysis not needed"
            
            # ✅ CREATE STATIC-ONLY RANSOMWARE RESULT AND STORE TO DATABASE
            result = {
                'status': 'success',
                'filename': file.filename,
                'signature_analysis': {
                    'performed': True,
                    'decision': signature_result['decision'],
                    'confidence': float(signature_result['confidence']),
                    'reason': signature_result['reason'],
                    'action': signature_result['action'],
                    'stage': signature_result['stage'],
                    'file_hash': signature_result.get('file_hash', ''),
                    'ratios': signature_result.get('ratios', {}),
                    'security_mode': signature_result.get('security_mode', 'BALANCED'),
                    'execution_time': signature_analysis_time
                },
                'static_analysis': {
                    'performed': True,
                    'prediction': int(static_prediction),
                    'prediction_label': 'Ransomware',
                    'confidence': float(static_confidence),
                    'probabilities': {
                        'benign': float(static_probabilities.get('benign', 0.5)),
                        'ransomware': float(static_probabilities.get('ransomware', 0.5))
                    },
                    'ensemble_details': static_result.get('ensemble_details', {}),
                    'explanation': static_result.get('explanation', {'available': False, 'reason': 'XAI data not found'}),
                    'feature_count': len(features),
                    'execution_time': static_analysis_time,
                    'status': 'completed'
                },
                'dynamic_analysis': {
                    'performed': False,
                    'status': 'skipped',
                    'reason': dynamic_reason,
                    'prediction': None,
                    'prediction_label': None,
                    'confidence': None,
                    'probabilities': {
                        'benign': None,
                        'ransomware': None
                    },
                    'analysis_type': None,
                    'execution_time': 0.0
                },
                'final_prediction': 1,
                'final_label': 'Ransomware',
                'prediction_label': 'Ransomware',
                'confidence': float(static_confidence),
                'analysis_mode': 'signature_static',
                'total_execution_time': time.time() - start_time,
                'decision_stage': 'static_analysis',
                'decision_reason': 'Static analysis detected ransomware with high confidence'
            }
            
            # ✅ STORE TO DATABASE BEFORE CLEANUP
            file_hash = calculate_file_hash(file_path)
            db.store_result(
                filename=file.filename,
                file_hash=file_hash,
                source="manual",
                prediction=1,
                analysis_result=result
            )
            
            cleanup_file(file_path)
            return jsonify(result)
            
        elif static_confidence < 0.7:
            # Low confidence threshold
            need_dynamic = True
            dynamic_reason = "Static analysis inconclusive - proceeding to dynamic analysis"
        else:
            # High confidence benign - continue to dynamic if available
            dynamic_reason = "Static analysis provided high-confidence benign result"

        # Initialize dynamic analysis structure (always present)
        dynamic_analysis_result = {
            'performed': False,
            'status': 'not_performed',
            'reason': dynamic_reason,
            'prediction': None,
            'prediction_label': None,
            'confidence': None,
            'probabilities': {
                'benign': None,
                'ransomware': None
            },
            'analysis_type': None,
            'execution_time': 0.0
        }

        # ========================================
        # STAGE 3: DYNAMIC ANALYSIS
        # ========================================
        if dynamic_available and static_prediction == 0:

            logger.info("STAGE 3: Starting dynamic analysis...")

            try:
                dynamic_start = time.time()
                
                # Get Cuckoo analysis (submit + wait + retrieve)
                cuckoo_report = analyze_file_with_cuckoo(file_path)

                if cuckoo_report:
                    # Run dynamic prediction using the clean brain
                    dynamic_result = dynamic_detector.predict_from_cuckoo_report(cuckoo_report)
                    
                    dynamic_analysis_time = time.time() - dynamic_start
                    
                    # Extract dynamic results
                    dynamic_prediction = 1 if dynamic_result.get('prediction') == 'ransomware' else 0
                    dynamic_confidence = dynamic_result.get('confidence', 0.0)
                    dynamic_probabilities = dynamic_result.get('probabilities', {'benign': 0.5, 'ransomware': 0.5})
                    
                    # Validate dynamic results
                    if dynamic_prediction not in [0, 1]:
                        dynamic_prediction = 0
                    if not isinstance(dynamic_confidence, (int, float)) or dynamic_confidence != dynamic_confidence:
                        dynamic_confidence = 0.5
                    if not isinstance(dynamic_probabilities, dict):
                        dynamic_probabilities = {'benign': 0.5, 'ransomware': 0.5}
                    
                    # Update dynamic analysis result
                    dynamic_analysis_result.update({
                        'performed': True,
                        'status': 'completed',
                        'reason': 'Dynamic analysis completed successfully',
                        'prediction': int(dynamic_prediction),
                        'prediction_label': 'Ransomware' if dynamic_prediction == 1 else 'Benign',
                        'confidence': float(dynamic_confidence),
                        'probabilities': {
                            'benign': float(dynamic_probabilities.get('benign', 0.5)),
                            'ransomware': float(dynamic_probabilities.get('ransomware', 0.5))
                        },
                        'analysis_type': 'ensemble' if has_ensemble else 'single_model',
                        'execution_time': dynamic_analysis_time,
                        'explanation': dynamic_result.get('explanation', {'available': False, 'reason': 'XAI data not provided by dynamic detector'}),
                        'ensemble_details': {
                            'individual_models': dynamic_result.get('individual_models', {}),
                            'voting_result': dynamic_result.get('voting_result', {}),
                            'analysis_type': 'ensemble' if dynamic_result.get('individual_models') else 'single_model'
                        }
                    })
                    
                    # Use dynamic result as final decision
                    final_prediction = dynamic_prediction
                    final_confidence = dynamic_confidence
                    decision_stage = 'dynamic_analysis'
                    
                else:
                    # Cuckoo failed, use static result
                    dynamic_analysis_result.update({
                        'performed': False,
                        'status': 'failed',
                        'reason': 'Cuckoo sandbox analysis failed - using static result',
                        'execution_time': time.time() - dynamic_start
                    })
                    
                    final_prediction = static_prediction
                    final_confidence = static_confidence
                    decision_stage = 'static_analysis'
                    
            except Exception as e:
                logger.error(f"Dynamic analysis error: {str(e)}")
                dynamic_analysis_result.update({
                    'performed': False,
                    'status': 'error',
                    'reason': f'Dynamic analysis error: {str(e)}',
                    'execution_time': time.time() - dynamic_start if 'dynamic_start' in locals() else 0.0
                })
                
                # Fall back to static result
                final_prediction = static_prediction
                final_confidence = static_confidence
                decision_stage = 'static_analysis'
        else:
            # No dynamic analysis needed/available
            final_prediction = static_prediction
            final_confidence = static_confidence
            decision_stage = 'static_analysis'
            
            if not dynamic_available:
                dynamic_analysis_result['reason'] = 'Dynamic detector not available'
                dynamic_analysis_result['status'] = 'unavailable'

        # ========================================
        # PREPARE FINAL RESULT WITH ALL STRUCTURES
        # ========================================
        
        result = {
            'status': 'success',
            'filename': file.filename,
            'signature_analysis': {
                'performed': True,
                'decision': signature_result['decision'],
                'confidence': float(signature_result['confidence']),
                'reason': signature_result['reason'],
                'action': signature_result['action'],
                'stage': signature_result['stage'],
                'file_hash': signature_result.get('file_hash', ''),
                'ratios': signature_result.get('ratios', {}),
                'security_mode': signature_result.get('security_mode', 'BALANCED'),
                'execution_time': signature_analysis_time
            },
            'static_analysis': {
                'performed': True,
                'prediction': int(static_prediction),
                'prediction_label': 'Ransomware' if static_prediction == 1 else 'Benign',
                'confidence': float(static_confidence),
                'probabilities': {
                    'benign': float(static_probabilities.get('benign', 0.5)),
                    'ransomware': float(static_probabilities.get('ransomware', 0.5))
                },
                'ensemble_details': static_result.get('ensemble_details', {}),
                'explanation': static_result.get('explanation', {'available': False, 'reason': 'XAI data not found'}),
                'feature_count': len(features),
                'execution_time': static_analysis_time,
                'status': 'completed'
            },
            'dynamic_analysis': dynamic_analysis_result,
            'final_prediction': int(final_prediction),
            'final_label': 'Ransomware' if final_prediction == 1 else 'Benign',
            'prediction_label': 'Ransomware' if final_prediction == 1 else 'Benign',
            'confidence': float(final_confidence),
            'analysis_mode': 'full_3_stage' if dynamic_analysis_result['performed'] else 'signature_static',
            'total_execution_time': time.time() - start_time,
            'decision_stage': decision_stage,
            'decision_reason': f'Final decision made by {decision_stage.replace("_", " ")}'
        }
        
        # ✅ STORE TO DATABASE BEFORE CLEANUP (for full pipeline results)
        file_hash = calculate_file_hash(file_path)
        db.store_result(
            filename=file.filename,
            file_hash=file_hash,
            source="manual",
            prediction=result.get('final_prediction', 0),
            analysis_result=result
        )
        
        # Clean up the file
        cleanup_file(file_path)

        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        cleanup_file(file_path)
        return jsonify({
            'status': 'error',
            'message': f'Error processing file: {str(e)}'
        }), 500

@api_bp.route('/signature-test', methods=['POST'])
def signature_test():
    """Endpoint for VirusTotal signature testing only"""
    
    # File validation
    is_valid, error_message, file = validate_file_upload(request, current_app.config['ALLOWED_EXTENSIONS'])
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': error_message
        }), 400

    try:
        # Save the file temporarily
        file_path = save_uploaded_file(file, current_app.config['UPLOAD_FOLDER'])
        logger.info(f"File saved for signature testing: {file_path}")
        
        # Perform signature analysis
        result = analyze_file_signature(file_path, "BALANCED")  # You can make this configurable
        
        # Clean up the file
        cleanup_file(file_path)
        
        # Return result
        return jsonify({
            'status': 'success',
            'filename': file.filename,
            'signature_analysis': result,
            **result  # Flatten the result for easier frontend access
        })
        
    except Exception as e:
        logger.error(f"Error in signature testing: {str(e)}")
        cleanup_file(file_path)
        return jsonify({
            'status': 'error',
            'message': f'Signature analysis failed: {str(e)}'
        }), 500

@api_bp.route('/static-analysis', methods=['POST'])
def static_analysis_only():
    """Endpoint to scan a file using ONLY static analysis (no signature, no dynamic)"""
    detector = current_app.detector
   
    if not detector.is_loaded:
        return jsonify({
            'status': 'error',
            'message': 'Static ensemble not initialized'
        }), 503
   
    # File validation
    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'message': 'No file provided'
        }), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': 'No file selected'
        }), 400

    if not allowed_file(file.filename, current_app.config['ALLOWED_EXTENSIONS']):
        return jsonify({
            'status': 'error',
            'message': f'File type not allowed. Allowed types: {", ".join(current_app.config["ALLOWED_EXTENSIONS"])}'
        }), 400

    try:
        # Save the file
        file_path = save_uploaded_file(file, current_app.config['UPLOAD_FOLDER'])
        logger.info(f"Static-only analysis for: {file_path}")
        
        # Start timing
        import time
        start_time = time.time()
        
        # ========================================
        # STATIC ANALYSIS ONLY
        # ========================================
        
        logger.info("Starting static-only ensemble analysis...")
        
        # Extract features
        static_start = time.time()
        features, error = extract_pe_features(file_path, current_app.config.get('STATIC_FEATURE_MAPPING'))
        
        if error:
            cleanup_file(file_path)
            return jsonify({
                'status': 'error',
                'message': f'Failed to extract features: {error}'
            }), 400
        
        # Make ensemble prediction
        static_result = detector.predict_ensemble_with_explanation(features, top_k=10)

        static_analysis_time = time.time() - static_start
        
        # Extract and validate results
        static_prediction = static_result.get('prediction', 0)
        static_confidence = static_result.get('confidence', 0.0)
        static_probabilities = static_result.get('probabilities', {'benign': 0.5, 'ransomware': 0.5})
        
        # Validation
        if static_prediction not in [0, 1]:
            static_prediction = 0
        if not isinstance(static_confidence, (int, float)) or static_confidence != static_confidence:
            static_confidence = 0.5
        if not isinstance(static_probabilities, dict):
            static_probabilities = {'benign': 0.5, 'ransomware': 0.5}
        
        # Prepare static-only result
        result = {
            'status': 'success',
            'filename': file.filename,
            'static_analysis': {
                'performed': True,
                'prediction': int(static_prediction),
                'prediction_label': 'Ransomware' if static_prediction == 1 else 'Benign',
                'confidence': float(static_confidence),
                'probabilities': {
                    'benign': float(static_probabilities['benign']),
                    'ransomware': float(static_probabilities['ransomware'])
                },
                'ensemble_details': static_result.get('ensemble_details', {}),
                'explanation': static_result.get('explanation', {'available': False, 'reason': 'XAI data not found'}),
                'feature_count': len(features),
                'execution_time': static_analysis_time,
                'status': 'success'
            },
            'final_prediction': int(static_prediction),
            'final_label': 'Ransomware' if static_prediction == 1 else 'Benign',
            'prediction_label': 'Ransomware' if static_prediction == 1 else 'Benign',
            'confidence': float(static_confidence),
            'analysis_mode': 'static_only',
            'total_execution_time': time.time() - start_time
        }
        
        # Clean up and return
        cleanup_file(file_path)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in static-only analysis: {str(e)}")
        cleanup_file(file_path)
        return jsonify({
            'status': 'error',
            'message': f'Static analysis failed: {str(e)}'
        }), 500

@api_bp.route('/dynamic-analysis', methods=['POST'])
def dynamic_analysis_only():
    """Endpoint for dynamic analysis only (bypasses static analysis)"""
    dynamic_detector = current_app.dynamic_detector
    
    # Check if dynamic model is loaded
    if dynamic_detector is None or not hasattr(dynamic_detector, 'is_loaded') or not dynamic_detector.is_loaded:
        return jsonify({
            'status': 'error',
            'message': 'Dynamic detector not available'
        }), 503
    
    # File validation
    is_valid, error_message, file = validate_file_upload(request, current_app.config['ALLOWED_EXTENSIONS'])
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': error_message
        }), 400

    try:
        # Save the file
        file_path = save_uploaded_file(file, current_app.config['UPLOAD_FOLDER'])
        logger.info(f"File saved for dynamic analysis: {file_path}")
        
        # Start timing
        import time
        start_time = time.time()
        
        # Direct to Cuckoo Analysis
        logger.info("Starting Cuckoo sandbox analysis...")
        cuckoo_report = analyze_file_with_cuckoo(file_path)
        
        cuckoo_time = time.time() - start_time
        
        # Dynamic Analysis with Clean Brain
        logger.info("Processing Cuckoo report with clean dynamic detector...")
        dynamic_start = time.time()
        
        # Check if we have ensemble models
        has_ensemble = hasattr(dynamic_detector, 'models') and bool(dynamic_detector.models)
        
        # Use the clean brain's prediction method
        dynamic_result = dynamic_detector.predict_from_cuckoo_report(cuckoo_report)
        
        dynamic_time = time.time() - dynamic_start
        total_time = time.time() - start_time
        
        # Convert prediction string to integer
        raw_prediction = dynamic_result.get('prediction', 'benign')
        prediction_int = 1 if raw_prediction == 'ransomware' else 0
        
        # Prepare result
        result = {
            'status': 'success',
            'filename': file.filename,
            'analysis_type': 'dynamic_only',
            'prediction': prediction_int,
            'prediction_label': 'Ransomware' if prediction_int == 1 else 'Benign',
            'confidence': dynamic_result.get('confidence', 0.0),
            'probabilities': dynamic_result.get('probabilities', {'benign': 0.5, 'ransomware': 0.5}),
            'feature_count': dynamic_result.get('feature_count', 0),
            'execution_times': {
                'cuckoo_analysis': round(cuckoo_time, 2),
                'dynamic_processing': round(dynamic_time, 2),
                'total_time': round(total_time, 2)
            }
        }
        
        # Add ensemble details if available
        if has_ensemble and 'individual_models' in dynamic_result:
            result['ensemble_details'] = {
                'individual_models': dynamic_result.get('individual_models', {}),
                'voting_result': dynamic_result.get('voting_result', {}),
                'analysis_type': 'ensemble'
            }
        else:
            result['ensemble_details'] = {'analysis_type': 'single_model'}

        # Add XAI explanations if available
        if 'explanation' in dynamic_result and dynamic_result['explanation']:
            explanation = dynamic_result['explanation']
            if 'ensemble_explanation' in explanation:
                ensemble_exp = explanation['ensemble_explanation']
                result['explanation'] = {
                    'available': True,
                    'top_features': ensemble_exp.get('top_features', [])[:10],
                    'explanation_text': ensemble_exp.get('explanation_text', ''),
                    'total_features_analyzed': ensemble_exp.get('total_features_analyzed', 0),
                    'models_with_explanations': ensemble_exp.get('models_with_explanations', 0)
                }
                # Add individual model explanations
                if 'model_explanations' in explanation:
                    result['explanation']['individual_models'] = explanation['model_explanations']
            else:
                result['explanation'] = {
                    'available': False,
                    'reason': 'Detailed explanations not available'
                }
        else:
            result['explanation'] = {
                'available': False,
                'reason': 'XAI not available for this analysis'
            }
            
        # Add Cuckoo analysis details
        result['cuckoo_analysis'] = {
            'status': 'completed',
            'analysis_duration': round(cuckoo_time, 2),
            'report_size': len(str(cuckoo_report)) if cuckoo_report else 0
        }
        
        # Clean up the file
        cleanup_file(file_path)
        
        return jsonify(result)
        
    except CuckooAnalysisError as e:
        logger.error(f"Cuckoo analysis failed: {str(e)}")
        cleanup_file(file_path)
        return jsonify({
            'status': 'error',
            'message': f'Cuckoo analysis failed: {str(e)}',
            'error_type': 'cuckoo_error'
        }), 500
        
    except Exception as e:
        logger.error(f"Dynamic analysis failed: {str(e)}")
        cleanup_file(file_path)
        return jsonify({
            'status': 'error',
            'message': f'Dynamic analysis failed: {str(e)}',
            'error_type': 'general_error'
        }), 500

@api_bp.route('/cuckoo-status', methods=['GET'])
def cuckoo_status():
    """Check Cuckoo Sandbox connectivity"""
    try:
        from utils.cuckoo_client import CuckooClient
        
        client = CuckooClient()
        is_connected = client.test_connection()
        
        if is_connected:
            return jsonify({
                'status': 'connected',
                'message': 'Cuckoo Sandbox is accessible',
                'api_url': client.base_url
            })
        else:
            return jsonify({
                'status': 'disconnected',
                'message': 'Cannot connect to Cuckoo Sandbox',
                'api_url': client.base_url
            }), 503
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Cuckoo status check failed: {str(e)}'
        }), 500
    
@api_bp.route('/recent-results', methods=['GET'])
def get_recent_results():
    """Get recent detection results for real-time updates"""
    results = db.get_recent_results(10)
    return jsonify(results)

@api_bp.route('/history', methods=['GET'])
def get_history():
    """Get all detection history"""
    results = db.get_all_results()
    return jsonify(results)

@api_bp.route('/database-info', methods=['GET'])
def get_database_info():
    """Get database statistics and recent entries"""
    try:
        # Get all results
        all_results = db.get_all_results()
        
        # Calculate statistics
        total_detections = len(all_results)
        manual_count = len([r for r in all_results if r['source'] == 'manual'])
        auto_count = len([r for r in all_results if r['source'] == 'auto'])
        threat_count = len([r for r in all_results if r['prediction'] == 1])
        safe_count = len([r for r in all_results if r['prediction'] == 0])
        
        return jsonify({
            'total_detections': total_detections,
            'manual_detections': manual_count,
            'auto_detections': auto_count,
            'threats_detected': threat_count,
            'safe_files': safe_count,
            'recent_results': all_results[:10]  # Last 10 results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@api_bp.route('/result-details/<int:result_id>')
def get_result_details(result_id):
    result_data = db.get_result_by_id(result_id)
    if not result_data:
        return jsonify({'error': 'Result not found'}), 404
    return jsonify(result_data)

# Add this route to your Flask app (likely in api.py or main app file)
