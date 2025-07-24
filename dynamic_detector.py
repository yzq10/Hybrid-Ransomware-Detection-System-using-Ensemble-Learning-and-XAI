"""
Clean Dynamic Ransomware Detector - The Brain
Simple orchestrator that coordinates feature extraction, ML prediction, and explanations
"""

import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Union
import logging

logger = logging.getLogger(__name__)

class DynamicDetector:
    """
    Simple brain that orchestrates dynamic ransomware detection
    """
    
    def __init__(self):
        """Initialize the brain"""
        self.models = {}
        self.svm_scaler = None
        self.feature_extractor = None
        self.xai_explainer = None
        self.is_loaded = False
    
    def load_models(self, models_dir: str, feature_mapping_file: str):
        """
        Load all ensemble models and components
        
        Args:
            models_dir: Directory with model files
            feature_mapping_file: Feature mapping JSON file
        """
        try:
            models_path = Path(models_dir)
            
            # Load ensemble models
            logger.info("Loading ensemble models...")
            self.models['xgboost'] = self._load_pickle(models_path / 'xgboost_model.pkl')
            self.models['randomforest'] = self._load_pickle(models_path / 'randomforest_model.pkl')
            self.models['svm'] = self._load_pickle(models_path / 'svm_model.pkl')
            self.svm_scaler = self._load_pickle(models_path / 'svm_scaler.pkl')
            
            # Initialize feature extractor
            from utils.dynamic_feature_extractor import DynamicFeatureExtractor
            self.feature_extractor = DynamicFeatureExtractor(feature_mapping_file)
            
            # Initialize XAI explainer
            from utils.dynamic_XAI import DynamicXAI
            self.xai_explainer = DynamicXAI(self.models, self.feature_extractor)
            
            self.is_loaded = True
            logger.info("✓ All components loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise
    
    def predict_from_cuckoo_report(self, cuckoo_report: Union[str, dict]) -> Dict:
        """
        Main prediction method - the brain's entry point
        
        Args:
            cuckoo_report: Cuckoo JSON report (string or dict)
            
        Returns:
            Complete prediction result with explanations
        """
        if not self.is_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")
        
        try:
            # Step 1: Extract features
            logger.debug("Extracting features from Cuckoo report...")
            features_df = self.feature_extractor.extract_features_from_cuckoo_json(cuckoo_report)
            
            # Step 2: Get ensemble predictions
            logger.debug("Getting ensemble predictions...")
            prediction_result = self._ensemble_predict(features_df)
            
            # Step 3: Get explanations
            logger.debug("Generating explanations...")
            explanation = self.xai_explainer.explain_prediction(features_df)
            
            # Step 4: Combine results
            final_result = {
                **prediction_result,
                'explanation': explanation,
                'feature_count': len(features_df.columns),
                'analysis_type': 'ensemble'
            }
            
            return final_result
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                'prediction': 'error',
                'confidence': 0.0,
                'probabilities': {'benign': 0.5, 'ransomware': 0.5},
                'error': str(e)
            }
    
    def _ensemble_predict(self, features_df: pd.DataFrame) -> Dict:
            """
            Get predictions from all models and combine using hard voting
            
            Args:
                features_df: Feature DataFrame
                
            Returns:
                Ensemble prediction result
            """
            individual_predictions = {}
            votes = []
            
            # Get prediction from each model
            for model_name, model in self.models.items():
                try:
                    if model_name == 'svm':
                        # SVM needs scaling - use scaler output directly (numpy array)
                        features_scaled = self.svm_scaler.transform(features_df)
                        pred = model.predict(features_scaled)[0]
                        proba = model.predict_proba(features_scaled)[0]
                    else:
                        # XGBoost and RandomForest use DataFrame directly
                        pred = model.predict(features_df)[0]
                        proba = model.predict_proba(features_df)[0]
                    
                    # Store individual result - Convert ALL NumPy types to Python types
                    individual_predictions[model_name] = {
                        'prediction': 'ransomware' if int(pred) == 1 else 'benign',
                        'confidence': float(max(proba).item()) if hasattr(max(proba), 'item') else float(max(proba)),
                        'probabilities': {
                            'benign': float(proba[0].item()) if hasattr(proba[0], 'item') else float(proba[0]),
                            'ransomware': float(proba[1].item()) if hasattr(proba[1], 'item') else float(proba[1])
                        }
                    }
                    votes.append(int(pred))
                    
                except Exception as e:
                    logger.warning(f"Model {model_name} prediction failed: {e}")
                    individual_predictions[model_name] = {'error': str(e)}
            
            # Hard voting (majority wins) + Average probabilities for confidence
            if votes:
                # 1. Majority voting for prediction
                ensemble_prediction = 1 if sum(votes) > len(votes) / 2 else 0
                
                # 2. Average probabilities for confidence display
                ransomware_probs = []
                benign_probs = []
                
                for model_name, pred_result in individual_predictions.items():
                    if 'error' not in pred_result:
                        ransomware_probs.append(pred_result['probabilities']['ransomware'])
                        benign_probs.append(pred_result['probabilities']['benign'])
                
                # Calculate average probabilities
                avg_ransomware_prob = sum(ransomware_probs) / len(ransomware_probs) if ransomware_probs else 0.5
                avg_benign_prob = sum(benign_probs) / len(benign_probs) if benign_probs else 0.5
                
                # Confidence is the probability of the predicted class
                ensemble_confidence = avg_ransomware_prob if ensemble_prediction == 1 else avg_benign_prob
                
            else:
                ensemble_prediction = 0
                ensemble_confidence = 0.5
                avg_ransomware_prob = 0.5
                avg_benign_prob = 0.5

            # Ensure all values are Python types
            ensemble_prediction = int(ensemble_prediction)
            ensemble_confidence = float(ensemble_confidence)
            avg_ransomware_prob = float(avg_ransomware_prob)
            avg_benign_prob = float(avg_benign_prob)

            return {
                'prediction': 'ransomware' if ensemble_prediction == 1 else 'benign',
                'confidence': ensemble_confidence,
                'probabilities': {
                    'benign': avg_benign_prob,
                    'ransomware': avg_ransomware_prob
                },
                'individual_models': individual_predictions,
                'voting_result': {
                    'votes': [int(v) for v in votes],
                    'majority_threshold': float(len(votes) / 2)
                }
            }
        
    
    def _load_pickle(self, file_path: Path) -> object:
        """Load pickle file"""
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models"""
        if not self.is_loaded:
            return {'loaded': False}
        
        return {
            'loaded': True,
            'type': 'ensemble',
            'models': list(self.models.keys()),
            'model_count': len(self.models),
            'feature_count': self.feature_extractor.get_feature_count() if self.feature_extractor else 0,
            'xai_available': self.xai_explainer is not None
        }


# Simple convenience function
def load_dynamic_detector(models_dir: str = "models/dynamic_ensemble", 
                        #   feature_mapping_file: str = "models/final_selected_feature_mapping.json") -> DynamicDetector:
                         feature_mapping_file: str = "models/RFE_selected_feature_names_dic.json") -> DynamicDetector:
                        # feature_mapping_file: str = "models/MLRan_combined_no_strings_feature_mapping.json") -> DynamicDetector:
    """Load and return ready-to-use detector"""
    detector = DynamicDetector()
    detector.load_models(models_dir, feature_mapping_file)
    return detector 