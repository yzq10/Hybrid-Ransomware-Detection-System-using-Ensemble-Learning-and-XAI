import pandas as pd
import numpy as np
import pickle
import json
import logging
from pathlib import Path
from typing import Dict, Tuple, Union
from utils.static_ensemble_XAI import StaticEnsembleXAIExplainer

logger = logging.getLogger(__name__)
logging.getLogger('shap').disabled = True

class RansomwareDetector:
    def __init__(self):
        # Ensemble models
        self.ensemble_models = {}
        self.svm_scaler = None
        self.xai_explainer = None
        self.feature_names = None
        self.is_loaded = False
        
        # API compatibility - these will be set when ensemble loads
        self.model = None  # Points to RandomForest for compatibility
        self.features = None  # Points to feature_names for compatibility

    def load_ensemble_models(self, ensemble_dir: str) -> bool:
        """
        Load the ensemble models (XGBoost + SVM + Random Forest)
        
        Args:
            ensemble_dir: Directory containing ensemble model files
            
        Returns:
            bool: True if loaded successfully
        """
        try:
            ensemble_path = Path(ensemble_dir)
            
            if not ensemble_path.exists():
                logger.error(f"Ensemble directory not found: {ensemble_dir}")
                return False
            
            logger.info(f"Loading ensemble models from: {ensemble_dir}")
            
            # Required ensemble files
            required_files = {
                'xgboost': 'xgboost_model.pkl',
                'svm': 'svm_model.pkl', 
                'randomforest': 'randomforest_model.pkl',
                'svm_scaler': 'svm_scaler.pkl',
                'feature_names': 'feature_names.json'
            }
            
            # Check if all required files exist
            missing_files = []
            for file_type, filename in required_files.items():
                file_path = ensemble_path / filename
                if not file_path.exists():
                    missing_files.append(filename)
            
            if missing_files:
                logger.error(f"Missing ensemble files: {missing_files}")
                return False
            
            # Load ensemble models
            logger.info("Loading individual ensemble models...")
            
            # Load XGBoost
            with open(ensemble_path / required_files['xgboost'], 'rb') as f:
                self.ensemble_models['xgboost'] = pickle.load(f)
            logger.info("✓ XGBoost model loaded")
            
            # Load SVM
            with open(ensemble_path / required_files['svm'], 'rb') as f:
                self.ensemble_models['svm'] = pickle.load(f)
            logger.info("✓ SVM model loaded")
            
            # Load Random Forest
            with open(ensemble_path / required_files['randomforest'], 'rb') as f:
                self.ensemble_models['randomforest'] = pickle.load(f)
            logger.info("✓ Random Forest model loaded")
            
            # Load SVM scaler
            with open(ensemble_path / required_files['svm_scaler'], 'rb') as f:
                self.svm_scaler = pickle.load(f)
            logger.info("✓ SVM scaler loaded")
            
            # Load feature names
            with open(ensemble_path / required_files['feature_names'], 'r') as f:
                feature_data = json.load(f)
                self.feature_names = feature_data.get('feature_names', [])
            logger.info(f"✓ Feature names loaded ({len(self.feature_names)} features)")
            
            # Validate models
            if not self._validate_ensemble_models():
                logger.error("Ensemble model validation failed")
                return False
            
            # Set status flags
            self.is_loaded = True
            
            # Set API compatibility attributes
            self.model = self.ensemble_models['randomforest']  # For existing API compatibility
            self.features = self.feature_names  # For existing API compatibility
            
            logger.info("✅ Ensemble models loaded successfully")
            logger.info(f"   Models: {list(self.ensemble_models.keys())}")
            logger.info(f"   Features: {len(self.feature_names)}")
            logger.info(f"   Mode: Ensemble (3-model voting)")
            
            # Initialize XAI explainer
            logger.info("Initializing static XAI explainer...")
            try:
                feature_names_file = ensemble_path / 'feature_names.json'
                self.xai_explainer = StaticEnsembleXAIExplainer(
                    models_dir=str(ensemble_path),
                    feature_names_file=str(feature_names_file) if feature_names_file.exists() else None
                )
                
                # Load models into XAI explainer
                if self.xai_explainer.load_models():
                    logger.info("✓ XAI explainer models loaded")
                else:
                    logger.warning("XAI explainer model loading failed")
                    self.xai_explainer = None
            except Exception as e:
                logger.warning(f"XAI explainer initialization failed: {e}")
                self.xai_explainer = None

            return True
            
        except Exception as e:
            logger.error(f"Error loading ensemble models: {str(e)}")
            return False
    
    def _validate_ensemble_models(self) -> bool:
        """Validate that all ensemble models are properly loaded"""
        try:
            # Check that all models exist
            required_models = ['xgboost', 'svm', 'randomforest']
            for model_name in required_models:
                if model_name not in self.ensemble_models:
                    logger.error(f"Missing ensemble model: {model_name}")
                    return False
                
                model = self.ensemble_models[model_name]
                if model is None:
                    logger.error(f"Ensemble model is None: {model_name}")
                    return False
                
                # Check if model has required methods
                if not hasattr(model, 'predict') or not hasattr(model, 'predict_proba'):
                    logger.error(f"Model missing required methods: {model_name}")
                    return False
            
            # Check SVM scaler
            if self.svm_scaler is None:
                logger.error("SVM scaler is None")
                return False
            
            # Check feature names
            if not self.feature_names or len(self.feature_names) == 0:
                logger.error("Feature names not loaded or empty")
                return False
            
            logger.info("✓ Ensemble model validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Ensemble validation error: {str(e)}")
            return False

    def predict(self, pe_data: Union[Dict, pd.DataFrame, np.ndarray]) -> Tuple[int, float, np.ndarray]:
        """
        Predict if a file is ransomware using ensemble voting
        
        Args:
            pe_data: Feature vector (dict, DataFrame, or numpy array)
            
        Returns:
            tuple: (prediction, confidence, probabilities)
                - prediction: 0 (benign) or 1 (ransomware)  
                - confidence: confidence score of the prediction
                - probabilities: [benign_prob, ransomware_prob]
        """
        if not self.is_loaded:
            logger.error("Ensemble models not loaded. Call load_ensemble_models() first.")
            return 0, 0.0, np.array([1.0, 0.0])
        
        try:
            # Convert features to DataFrame with correct column names
            if isinstance(pe_data, dict):
                # Convert dict to DataFrame
                features_df = pd.DataFrame([pe_data])
            elif isinstance(pe_data, np.ndarray):
                # Convert numpy array to DataFrame with feature names
                if len(pe_data.shape) == 1:
                    pe_data = pe_data.reshape(1, -1)
                features_df = pd.DataFrame(pe_data, columns=self.feature_names[:pe_data.shape[1]])
            elif isinstance(pe_data, pd.DataFrame):
                features_df = pe_data.copy()
            else:
                raise ValueError(f"Unsupported feature type: {type(pe_data)}")
            
            # Ensure we have the right number of features
            expected_features = len(self.feature_names)
            actual_features = features_df.shape[1]
            
            if actual_features != expected_features:
                logger.warning(f"Feature count mismatch: expected {expected_features}, got {actual_features}")
                
                # Pad with zeros if we have fewer features
                if actual_features < expected_features:
                    missing_features = expected_features - actual_features
                    zeros = pd.DataFrame(np.zeros((features_df.shape[0], missing_features)), 
                                    columns=self.feature_names[actual_features:])
                    features_df = pd.concat([features_df, zeros], axis=1)
                    logger.warning(f"Padded with {missing_features} zero features")
                
                # Truncate if we have more features
                elif actual_features > expected_features:
                    features_df = features_df.iloc[:, :expected_features]
                    logger.warning(f"Truncated to {expected_features} features")
            
            # Ensure column names match
            features_df.columns = self.feature_names[:features_df.shape[1]]
            
            # Get predictions from each model with error handling
            individual_predictions = {}
            individual_probabilities = {}
            successful_models = 0
            
            # XGBoost prediction (uses raw features)
            try:
                xgb_pred = self.ensemble_models['xgboost'].predict(features_df)[0]
                xgb_proba = self.ensemble_models['xgboost'].predict_proba(features_df)[0]
                
                # VALIDATION: Check for valid prediction
                if xgb_pred in [0, 1] and len(xgb_proba) == 2 and not np.isnan(xgb_proba).any():
                    individual_predictions['xgboost'] = int(xgb_pred)
                    individual_probabilities['xgboost'] = xgb_proba
                    successful_models += 1
                    logger.debug(f"XGBoost: pred={xgb_pred}, proba={xgb_proba}")
                else:
                    logger.warning(f"XGBoost returned invalid values: pred={xgb_pred}, proba={xgb_proba}")
            except Exception as e:
                logger.error(f"XGBoost prediction failed: {e}")
            
            # Random Forest prediction (uses raw features)
            try:
                rf_pred = self.ensemble_models['randomforest'].predict(features_df)[0]
                rf_proba = self.ensemble_models['randomforest'].predict_proba(features_df)[0]
                
                # VALIDATION: Check for valid prediction
                if rf_pred in [0, 1] and len(rf_proba) == 2 and not np.isnan(rf_proba).any():
                    individual_predictions['randomforest'] = int(rf_pred)
                    individual_probabilities['randomforest'] = rf_proba
                    successful_models += 1
                    logger.debug(f"Random Forest: pred={rf_pred}, proba={rf_proba}")
                else:
                    logger.warning(f"Random Forest returned invalid values: pred={rf_pred}, proba={rf_proba}")
            except Exception as e:
                logger.error(f"Random Forest prediction failed: {e}")
            
            # SVM prediction (requires scaling)
            try:
                features_scaled = self.svm_scaler.transform(features_df)
                svm_pred = self.ensemble_models['svm'].predict(features_scaled)[0]
                svm_proba = self.ensemble_models['svm'].predict_proba(features_scaled)[0]
                
                # VALIDATION: Check for valid prediction
                if svm_pred in [0, 1] and len(svm_proba) == 2 and not np.isnan(svm_proba).any():
                    individual_predictions['svm'] = int(svm_pred)
                    individual_probabilities['svm'] = svm_proba
                    successful_models += 1
                    logger.debug(f"SVM: pred={svm_pred}, proba={svm_proba}")
                else:
                    logger.warning(f"SVM returned invalid values: pred={svm_pred}, proba={svm_proba}")
            except Exception as e:
                logger.error(f"SVM prediction failed: {e}")
            
            # Check if we have enough successful predictions
            if successful_models == 0:
                logger.error("All models failed to make valid predictions")
                return 0, 0.5, np.array([0.5, 0.5])
            
            # Majority voting (with fallback for insufficient models)
            votes = list(individual_predictions.values())
            
            if len(votes) >= 2:
                # Normal majority voting
                vote_counts = {0: votes.count(0), 1: votes.count(1)}
                ensemble_prediction = 1 if vote_counts[1] >= 2 else 0
            elif len(votes) == 1:
                # Only one model succeeded
                ensemble_prediction = votes[0]
                logger.warning("Only one model succeeded, using its prediction")
            else:
                # No models succeeded (shouldn't reach here due to earlier check)
                logger.error("No valid predictions available")
                return 0, 0.5, np.array([0.5, 0.5])
            
            # Calculate ensemble probabilities (average of individual probabilities)
            if individual_probabilities:
                probabilities_array = np.array(list(individual_probabilities.values()))
                avg_probabilities = np.mean(probabilities_array, axis=0)
                
                # VALIDATION: Ensure probabilities are valid
                if len(avg_probabilities) != 2 or np.isnan(avg_probabilities).any():
                    logger.warning(f"Invalid averaged probabilities: {avg_probabilities}")
                    avg_probabilities = np.array([0.5, 0.5])
            else:
                avg_probabilities = np.array([0.5, 0.5])
            
            # Calculate confidence as the probability of the predicted class
            confidence = float(avg_probabilities[ensemble_prediction])
            
            # FINAL VALIDATION: Ensure all return values are valid
            if ensemble_prediction not in [0, 1]:
                logger.error(f"Invalid ensemble_prediction: {ensemble_prediction}")
                ensemble_prediction = 0
            
            if not isinstance(confidence, (int, float)) or np.isnan(confidence) or confidence < 0 or confidence > 1:
                logger.error(f"Invalid confidence: {confidence}")
                confidence = 0.5
            
            if len(avg_probabilities) != 2 or np.isnan(avg_probabilities).any():
                logger.error(f"Invalid avg_probabilities: {avg_probabilities}")
                avg_probabilities = np.array([0.5, 0.5])
            
            logger.debug(f"Ensemble voting: {successful_models} models succeeded → prediction={ensemble_prediction}, confidence={confidence:.3f}")
            
            return int(ensemble_prediction), float(confidence), avg_probabilities
            
        except Exception as e:
            logger.error(f"Error in ensemble prediction: {str(e)}")
            logger.error(f"Exception details: {type(e).__name__}: {e}")
            
            # Enhanced fallback to random forest if ensemble fails
            if 'randomforest' in self.ensemble_models:
                try:
                    logger.warning("Falling back to Random Forest model")
                    # Ensure features_df exists
                    if 'features_df' in locals():
                        rf_pred = self.ensemble_models['randomforest'].predict(features_df)[0]
                        rf_proba = self.ensemble_models['randomforest'].predict_proba(features_df)[0]
                        
                        # Validate fallback prediction
                        if rf_pred in [0, 1] and len(rf_proba) == 2 and not np.isnan(rf_proba).any():
                            return int(rf_pred), float(max(rf_proba)), rf_proba
                        else:
                            logger.warning(f"Fallback RF also returned invalid values: pred={rf_pred}, proba={rf_proba}")
                except Exception as fallback_error:
                    logger.error(f"Fallback to Random Forest also failed: {fallback_error}")
            
            # Ultimate fallback
            logger.warning("Using ultimate fallback values")
            return 0, 0.5, np.array([0.5, 0.5])

    def predict_ensemble(self, pe_data):
        """
        Predict using ensemble and return detailed results for API compatibility
        """
        # Use the existing predict method
        prediction, confidence, probabilities = self.predict(pe_data)
        
        # Get individual model results for detailed response
        individual_results = {}
        
        try:
            # Convert features to the right format
            if isinstance(pe_data, dict):
                features_df = pd.DataFrame([pe_data])
            elif isinstance(pe_data, np.ndarray):
                if len(pe_data.shape) == 1:
                    pe_data = pe_data.reshape(1, -1)
                features_df = pd.DataFrame(pe_data, columns=self.feature_names[:pe_data.shape[1]])
            else:
                features_df = pe_data.copy()
            
            # Ensure we have the right number of features
            if features_df.shape[1] != len(self.feature_names):
                if features_df.shape[1] < len(self.feature_names):
                    # Pad with zeros
                    missing_cols = len(self.feature_names) - features_df.shape[1]
                    zeros_df = pd.DataFrame(np.zeros((features_df.shape[0], missing_cols)), 
                                        columns=self.feature_names[features_df.shape[1]:])
                    features_df = pd.concat([features_df, zeros_df], axis=1)
                else:
                    # Truncate
                    features_df = features_df.iloc[:, :len(self.feature_names)]
            
            # Ensure column names match
            features_df.columns = self.feature_names
            
            # Get individual model predictions
            for model_name, model in self.ensemble_models.items():
                try:
                    if model_name == 'svm':
                        # SVM needs scaling
                        features_scaled = self.svm_scaler.transform(features_df)
                        pred = model.predict(features_scaled)[0]
                        proba = model.predict_proba(features_scaled)[0]
                    else:
                        # XGBoost and Random Forest use raw features
                        pred = model.predict(features_df)[0]
                        proba = model.predict_proba(features_df)[0]
                    
                    individual_results[model_name] = {
                        'prediction': int(pred),
                        'prediction_label': 'Ransomware' if pred == 1 else 'Benign',
                        'confidence': float(max(proba)),
                        'probabilities': {
                            'benign': float(proba[0]),
                            'ransomware': float(proba[1])
                        }
                    }
                except Exception as e:
                    logger.warning(f"Error getting individual prediction from {model_name}: {e}")
                    individual_results[model_name] = {
                        'prediction': int(prediction),  # Fallback to ensemble result
                        'prediction_label': 'Ransomware' if prediction == 1 else 'Benign',
                        'confidence': float(confidence),
                        'probabilities': {
                            'benign': float(probabilities[0]),
                            'ransomware': float(probabilities[1])
                        },
                        'error': str(e)
                    }
        
        except Exception as e:
            logger.error(f"Error getting individual model results: {e}")
            individual_results = {}
        
        # Return detailed ensemble results
        return {
            'prediction': int(prediction),
            'confidence': float(confidence),
            'probabilities': {
                'benign': float(probabilities[0]),
                'ransomware': float(probabilities[1])
            },
            'ensemble_details': {
                'individual_models': individual_results,
                'voting_strategy': 'majority_vote_2_of_3',
                'model_count': len(self.ensemble_models),
                'models': list(self.ensemble_models.keys())
            },
            'feature_count': len(self.feature_names) if self.feature_names else 0
        }

    def predict_ensemble_with_explanation(self, pe_data, top_k: int = 10):
        """
        Predict using ensemble and return detailed results with XAI explanations
        
        Args:
            pe_data: PE feature data
            top_k: Number of top features to explain
            
        Returns:
            Dictionary with prediction results and explanations
        """
        # Get standard ensemble prediction
        standard_result = self.predict_ensemble(pe_data)
        
        # Add XAI explanation if available
        if self.xai_explainer and hasattr(self.xai_explainer, 'is_loaded') and self.xai_explainer.is_loaded:
            try:
                # Convert pe_data to numpy array
                if isinstance(pe_data, dict):
                    features_df = pd.DataFrame([pe_data])
                    features_array = features_df.values[0]
                elif isinstance(pe_data, pd.DataFrame):
                    features_array = pe_data.values[0]
                elif isinstance(pe_data, np.ndarray):
                    if pe_data.ndim == 2:
                        features_array = pe_data[0]
                    else:
                        features_array = pe_data
                else:
                    features_array = np.array(pe_data)
                
                explanation = self.xai_explainer.explain_prediction(features_array, top_k)
                standard_result['explanation'] = explanation
                
            except Exception as e:
                logger.error(f"XAI explanation failed: {e}")
                standard_result['explanation'] = {'error': f'Explanation failed: {str(e)}'}
        else:
            standard_result['explanation'] = {'available': False, 'reason': 'XAI explainer not loaded'}
        
        return standard_result

    def initialize_static_xai_explainer(self, background_data: np.ndarray = None):
        """
        Initialize XAI explainer with background data
        Auto-generates background data if none provided
        """
        if self.xai_explainer and not getattr(self.xai_explainer, 'is_loaded', False):
            try:
                # Auto-generate background data if not provided
                if background_data is None:
                    logger.info("Generating synthetic background data for static XAI explainer...")
                    n_features = len(self.feature_names) if self.feature_names else 225
                    
                    # Create diverse background: zeros, ones, and random binary
                    background_data = np.vstack([
                        np.zeros((20, n_features)),  # 20 samples of all zeros
                        np.ones((20, n_features)),   # 20 samples of all ones  
                        np.random.randint(0, 2, (40, n_features))  # 40 random binary samples
                    ]).astype(float)
                    
                    logger.info(f"Generated {background_data.shape[0]} background samples with {n_features} features")
                
                self.xai_explainer.create_explainers(background_data)
                logger.info("✓ Static XAI explainer initialized with background data")
            except Exception as e:
                logger.error(f"Failed to initialize static XAI explainer: {e}")

    def get_model_info(self) -> Dict:
        """Get information about loaded ensemble models"""
        
        if self.is_loaded:
            model_info = {
                'type': 'ensemble',
                'models': list(self.ensemble_models.keys()),
                'model_count': len(self.ensemble_models),
                'feature_count': len(self.feature_names) if self.feature_names else 0,
                'voting_strategy': 'majority_vote',
                'individual_models': {
                    'xgboost': type(self.ensemble_models.get('xgboost')).__name__ if 'xgboost' in self.ensemble_models else None,
                    'svm': type(self.ensemble_models.get('svm')).__name__ if 'svm' in self.ensemble_models else None,
                    'randomforest': type(self.ensemble_models.get('randomforest')).__name__ if 'randomforest' in self.ensemble_models else None
                },
                'svm_preprocessing': 'StandardScaler' if self.svm_scaler else None,
                'loaded': True
            }
            
            # Add XAI information
            model_info['xai_available'] = self.xai_explainer is not None
            model_info['xai_loaded'] = (self.xai_explainer is not None and 
                                    hasattr(self.xai_explainer, 'is_loaded') and 
                                    self.xai_explainer.is_loaded)
            
            return model_info
        else:
            return {
                'type': 'ensemble',
                'loaded': False,
                'error': 'Models not loaded'
            }
        
    def get_ensemble_details(self) -> Dict:
        """Get detailed information about the last prediction (for debugging)"""
        # This could be enhanced to store and return details from the last prediction
        # For now, return basic ensemble configuration
        return {
            'ensemble_composition': list(self.ensemble_models.keys()) if self.ensemble_models else [],
            'voting_strategy': 'majority_vote_2_of_3',
            'preprocessing': {
                'xgboost': 'raw_features',
                'randomforest': 'raw_features', 
                'svm': 'standardscaler_transformed'
            },
            'confidence_calculation': 'average_probabilities'
        }

    # Legacy compatibility methods (minimal implementations)
    def load_model(self, model_path: str, preprocessor_path: str) -> bool:
        """Legacy compatibility - redirects to ensemble loading"""
        logger.warning("load_model() is deprecated. Use load_ensemble_models() instead.")
        # Try to infer ensemble directory from model path
        model_dir = Path(model_path).parent
        return self.load_ensemble_models(str(model_dir))

    @property
    def preprocessor(self):
        """Legacy compatibility property"""
        return self.svm_scaler  # Return SVM scaler as preprocessor


# Example usage
if __name__ == "__main__":
    detector = RansomwareDetector()
    
    # Load ensemble models
    ensemble_loaded = detector.load_ensemble_models("models/static_ensemble")
    
    if ensemble_loaded:
        logger.info("✅ Ensemble models loaded successfully")
        
        # Example prediction with sample data
        sample_pe_data = {
            # This would typically contain ~450 features (PE + API)
            # For demo purposes, showing a few sample features
            'PE_e_magic': 23117,
            'PE_Machine': 332,
            'PE_NumberOfSections': 3,
            'API_CreateFileA': 1,
            'API_RegOpenKeyA': 0,
            # ... more features would be here
        }
        
        prediction, confidence, probabilities = detector.predict(sample_pe_data)
        
        if prediction == 0:
            logger.info(f"Prediction: Benign (Confidence: {confidence:.2f})")
        else:
            logger.info(f"Prediction: Ransomware (Confidence: {confidence:.2f})")
        
        logger.info(f"Probabilities: Benign={probabilities[0]:.2f}, Ransomware={probabilities[1]:.2f}")
        
        # Show model info
        model_info = detector.get_model_info()
        logger.info(f"Model Info: {model_info}")
        
    else:
        logger.error("❌ Failed to load ensemble models")