"""
Static Ensemble XAI Explainer for Ransomware Detection
Provides SHAP-based explanations for XGBoost + SVM + Random Forest ensemble
"""

import pickle
import json
import numpy as np
import pandas as pd
import shap
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union
import os

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Only show critical errors
logger = logging.getLogger(__name__)

# More aggressive SHAP silencing
import warnings
warnings.filterwarnings('ignore')

logging.getLogger('shap').setLevel(logging.CRITICAL)
logging.getLogger('shap.explainers').setLevel(logging.CRITICAL)
logging.getLogger('shap.explainers.permutation').setLevel(logging.CRITICAL)
logging.getLogger('shap.plots').setLevel(logging.CRITICAL)

# Disable progress bars completely
os.environ['SHAP_DISABLE_PROGRESS'] = '1'
os.environ['SHAP_SILENT'] = '1'

class StaticEnsembleXAIExplainer:
    """
    XAI Explainer for Static Ransomware Detection Ensemble
    Provides SHAP explanations for individual models and ensemble decisions
    """
    
    def __init__(self, models_dir: str = "models/static_ensemble", feature_names_file: str = None):
        """
        Initialize the static ensemble XAI explainer
        
        Args:
            models_dir: Directory containing saved ensemble models
            feature_names_file: Path to feature names JSON file
        """
        self.models_dir = Path(models_dir)
        self.models = {}
        self.svm_scaler = None
        self.explainers = {}
        self.feature_names = []
        self.is_loaded = False
        
        # Load feature names if provided
        if feature_names_file:
            self.load_feature_names(feature_names_file)
    
    def load_feature_names(self, feature_names_file: str):
        """
        Load feature names from JSON file
        
        Args:
            feature_names_file: Path to JSON file with feature names
        """
        try:
            with open(feature_names_file, 'r') as f:
                feature_data = json.load(f)
                self.feature_names = feature_data.get('feature_names', [])
            
            logger.info(f"Loaded {len(self.feature_names)} feature names")
            
        except Exception as e:
            logger.warning(f"Could not load feature names: {e}")
            logger.warning("Will use feature indices instead of names")
    
    def load_models(self):
        """
        Load all trained ensemble models and SVM scaler
        """
        try:
            logger.info("Loading static ensemble models...")
            
            # Load individual models
            model_files = {
                'xgboost': self.models_dir / 'xgboost_model.pkl',
                'svm': self.models_dir / 'svm_model.pkl',
                'randomforest': self.models_dir / 'randomforest_model.pkl'
            }
            
            for model_name, model_file in model_files.items():
                if model_file.exists():
                    with open(model_file, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                    logger.info(f"✓ Loaded {model_name}")
                else:
                    logger.error(f"✗ Model file not found: {model_file}")
                    return False
            
            # Load SVM scaler
            scaler_file = self.models_dir / 'svm_scaler.pkl'
            if scaler_file.exists():
                with open(scaler_file, 'rb') as f:
                    self.svm_scaler = pickle.load(f)
                logger.info("✓ Loaded SVM scaler")
            else:
                logger.error("✗ SVM scaler not found")
                return False
            
            logger.info(f"Loaded {len(self.models)} models successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def create_explainers(self, background_data: np.ndarray):
        """
        Create SHAP explainers for each model type
        
        Args:
            background_data: Representative sample of training data for explainers
        """
        try:
            logger.info("Creating SHAP explainers...")
            
            # Convert to DataFrame with feature names
            if len(self.feature_names) > 0:
                background_df = pd.DataFrame(background_data, columns=self.feature_names[:background_data.shape[1]])
            else:
                background_df = pd.DataFrame(background_data)
            
            # Create explainer for XGBoost (TreeExplainer)
            if 'xgboost' in self.models:
                self.explainers['xgboost'] = shap.TreeExplainer(
                    self.models['xgboost']
                )
                logger.info("✓ Created TreeExplainer for XGBoost")
            
            # Create explainer for Random Forest (TreeExplainer)
            if 'randomforest' in self.models:
                self.explainers['randomforest'] = shap.TreeExplainer(
                    self.models['randomforest']
                )
                logger.info("✓ Created TreeExplainer for Random Forest")
            
            # Create explainer for SVM (use faster KernelExplainer with smaller sample)
            if 'svm' in self.models:
                try:
                    # Scale background data for SVM
                    background_scaled = self.svm_scaler.transform(background_df)
                    
                    # Use smaller sample for faster computation
                    sample_size = min(20, background_df.shape[0])  # Much smaller sample
                    
                    # Use KernelExplainer with reduced sample
                    self.explainers['svm'] = shap.KernelExplainer(
                        lambda x: self.models['svm'].predict_proba(self.svm_scaler.transform(pd.DataFrame(x, columns=background_df.columns)))[:, 1],
                        background_df.iloc[:sample_size]  # Use only first 20 samples
                    )
                    logger.info("✓ Created KernelExplainer for SVM (optimized)")
                except Exception as e:
                    logger.warning(f"Failed to create explainer for SVM: {e}")
                    logger.info("⚠️  SVM will be excluded from XAI explanations")
            
            # Mark as loaded if we have at least one explainer
            if self.explainers:
                self.is_loaded = True
                logger.info(f"✅ SHAP explainers created successfully! ({len(self.explainers)} models)")
            else:
                self.is_loaded = False
                logger.error("❌ No SHAP explainers could be created!")
            
        except Exception as e:
            logger.error(f"Error creating explainers: {e}")
            self.is_loaded = False
    
    def hard_voting_predict(self, X: np.ndarray) -> np.ndarray:
        """
        Ensemble hard voting prediction
        
        Args:
            X: Feature matrix
            
        Returns:
            Ensemble predictions
        """
        if not self.is_loaded:
            raise RuntimeError("Models not loaded. Call load_models() and create_explainers() first.")
        
        # Convert to DataFrame with feature names
        if len(self.feature_names) > 0:
            X_df = pd.DataFrame(X, columns=self.feature_names[:X.shape[1]])
        else:
            X_df = pd.DataFrame(X)
        
        predictions = []
        
        # XGBoost prediction
        if 'xgboost' in self.models:
            pred = self.models['xgboost'].predict(X_df)
            predictions.append(pred)
        
        # Random Forest prediction
        if 'randomforest' in self.models:
            pred = self.models['randomforest'].predict(X_df)
            predictions.append(pred)
        
        # SVM prediction (requires scaling)
        if 'svm' in self.models:
            X_scaled = self.svm_scaler.transform(X_df)
            pred = self.models['svm'].predict(X_scaled)
            predictions.append(pred)
        
        predictions = np.array(predictions)
        ensemble_predictions = (np.sum(predictions, axis=0) >= 2).astype(int)
        
        return ensemble_predictions
    
    def explain_prediction(self, features: np.ndarray, top_k: int = 10) -> Dict:
        """
        Generate comprehensive explanation for a single prediction
        
        Args:
            features: Single sample feature vector (1D array)
            top_k: Number of top contributing features to return
            
        Returns:
            Dictionary with explanations for individual models and ensemble
        """
        if not self.is_loaded:
            raise RuntimeError("Explainers not loaded. Call create_explainers() first.")
        
        # Ensure features is 2D for sklearn
        if features.ndim == 1:
            features_2d = features.reshape(1, -1)
        else:
            features_2d = features
        
        # Convert to DataFrame with feature names
        if len(self.feature_names) > 0:
            features_df = pd.DataFrame(features_2d, columns=self.feature_names[:features_2d.shape[1]])
        else:
            features_df = pd.DataFrame(features_2d)
        
        explanations = {
            'individual_models': {},
            'ensemble': {},
            'feature_contributions': {}
        }
        
        # Get individual model explanations
        all_shap_values = {}
        
        for model_name, explainer in self.explainers.items():
            try:
                # Get SHAP values with proper handling for different explainer types
                if model_name in ['xgboost', 'randomforest']:
                    # Tree explainers return values for each class, we want class 1 (ransomware)
                    shap_values = explainer.shap_values(features_df)
                    if isinstance(shap_values, list):
                        shap_values = shap_values[1]  # Class 1 (ransomware)
                elif model_name == 'svm':
                    # For KernelExplainer on SVM - limit sample size for speed
                    shap_values = explainer.shap_values(features_df, nsamples=50)  # Limit samples for speed
                    if isinstance(shap_values, list) and len(shap_values) > 1:
                        shap_values = shap_values[1]  # Class 1
                else:
                    # Generic handling
                    shap_values = explainer.shap_values(features_df)
                
                # Handle different SHAP value shapes consistently
                if isinstance(shap_values, np.ndarray):
                    if shap_values.ndim == 3 and shap_values.shape[0] == 1:
                        # Shape (1, n_features, n_classes) -> get class 1 (ransomware)
                        shap_values_1d = shap_values[0, :, 1]
                    elif shap_values.ndim == 2 and shap_values.shape[0] == 1:
                        # Shape (1, n_features) -> flatten to (n_features,)
                        shap_values_1d = shap_values[0]
                    elif shap_values.ndim == 2 and shap_values.shape[1] == 2:
                        # Shape (n_features, n_classes) -> get class 1
                        shap_values_1d = shap_values[:, 1]
                    elif shap_values.ndim == 1:
                        # Already 1D
                        shap_values_1d = shap_values
                    else:
                        logger.warning(f"Unexpected SHAP values shape for {model_name}: {shap_values.shape}")
                        continue
                else:
                    logger.warning(f"SHAP values not numpy array for {model_name}: {type(shap_values)}")
                    continue
                
                # Store SHAP values
                all_shap_values[model_name] = shap_values_1d
                
                # Get model prediction
                if model_name == 'svm':
                    # SVM requires scaling
                    features_scaled = self.svm_scaler.transform(features_df)
                    prediction = self.models[model_name].predict(features_scaled)[0]
                    probabilities = self.models[model_name].predict_proba(features_scaled)[0]
                else:
                    prediction = self.models[model_name].predict(features_df)[0]
                    probabilities = self.models[model_name].predict_proba(features_df)[0]
                
                # Get top features for this individual model
                model_top_features = self._get_individual_model_top_features(
                    shap_values_1d, 
                    features[0] if features.ndim > 1 else features, 
                    3
                )

                explanations['individual_models'][model_name] = {
                    'prediction': int(prediction),
                    'prediction_label': 'Ransomware' if prediction == 1 else 'Benign',
                    'probabilities': {
                        'benign': float(probabilities[0]),
                        'ransomware': float(probabilities[1])
                    },
                    'confidence': float(max(probabilities)),
                    'shap_values': shap_values_1d.tolist(),
                    'top_features': model_top_features
                }
                
            except Exception as e:
                logger.error(f"Error explaining {model_name}: {e}")
                explanations['individual_models'][model_name] = {
                    'error': str(e)
                }
        
        # Get ensemble prediction and explanation
        if all_shap_values:
            ensemble_pred = self.hard_voting_predict(features_2d)[0]
        else:
            # Fallback when no SHAP values available
            predictions = []
            for model_name, model in self.models.items():
                if model_name == 'svm':
                    features_scaled = self.svm_scaler.transform(features_df)
                    predictions.append(model.predict(features_scaled)[0])
                else:
                    predictions.append(model.predict(features_df)[0])
            ensemble_pred = int(sum(predictions) >= 2)
        
        # Average SHAP values for ensemble explanation
        if all_shap_values:
            # Convert all SHAP values to numpy arrays and ensure same shape
            shap_arrays = []
            for model_name, shap_vals in all_shap_values.items():
                if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 1:
                    shap_arrays.append(shap_vals)
                else:
                    logger.warning(f"Skipping {model_name} SHAP values due to shape issues")
            
            if shap_arrays:
                # Stack arrays and compute mean
                stacked_shap = np.stack(shap_arrays, axis=0)  # Shape: (n_models, n_features)
                ensemble_shap = np.mean(stacked_shap, axis=0)  # Shape: (n_features,)
                
                explanations['ensemble'] = {
                    'prediction': int(ensemble_pred),
                    'prediction_label': 'Ransomware' if ensemble_pred == 1 else 'Benign',
                    'voting_breakdown': self._get_voting_breakdown(features_df),
                    'ensemble_shap_values': ensemble_shap.tolist()
                }
            else:
                explanations['ensemble'] = {
                    'prediction': int(ensemble_pred),
                    'prediction_label': 'Ransomware' if ensemble_pred == 1 else 'Benign',
                    'voting_breakdown': self._get_voting_breakdown(features_df),
                    'error': 'Could not compute ensemble SHAP values'
                }
        
        # Get top contributing features
        if all_shap_values and len(shap_arrays) > 0:
            explanations['feature_contributions'] = self._get_top_features(
                ensemble_shap,
                features[0] if features.ndim > 1 else features,
                top_k
            )
        
        return explanations
    
    def _get_individual_model_top_features(self, shap_values: np.ndarray, feature_values: np.ndarray, top_k: int = 3) -> List[Dict]:
        """Get top contributing features for individual model"""
        
        # Get absolute SHAP values for ranking
        abs_shap = np.abs(shap_values)
        
        # Get top k indices
        top_indices = np.argsort(abs_shap)[-top_k:][::-1]
        
        top_features = []
        
        for idx in top_indices:
            # Look up feature name
            feature_name = f"Feature_{idx}"  # Default fallback
            
            if idx < len(self.feature_names):
                feature_name = self.feature_names[idx]
            
            top_features.append({
                'feature_id': str(idx),
                'feature_name': feature_name,
                'shap_value': float(shap_values[idx]),
                'contribution_type': 'Increases Risk' if shap_values[idx] > 0 else 'Decreases Risk'
            })
        
        return top_features

    def _get_voting_breakdown(self, features_df: pd.DataFrame) -> Dict:
        """Get detailed voting breakdown for ensemble"""
        breakdown = {}
        
        for model_name, model in self.models.items():
            try:
                if model_name == 'svm':
                    features_scaled = self.svm_scaler.transform(features_df)
                    pred = model.predict(features_scaled)[0]
                    proba = model.predict_proba(features_scaled)[0]
                else:
                    pred = model.predict(features_df)[0]
                    proba = model.predict_proba(features_df)[0]
                
                breakdown[model_name] = {
                    'vote': int(pred),
                    'vote_label': 'Ransomware' if pred == 1 else 'Benign',
                    'confidence': float(max(proba))
                }
            except Exception as e:
                logger.error(f"Error getting vote from {model_name}: {e}")
                breakdown[model_name] = {
                    'vote': 0,
                    'vote_label': 'Error',
                    'confidence': 0.0,
                    'error': str(e)
                }
        
        # Count votes
        valid_votes = [vote['vote'] for vote in breakdown.values() if 'error' not in vote]
        ransomware_votes = sum(valid_votes)
        benign_votes = len(valid_votes) - ransomware_votes
        
        breakdown['summary'] = {
            'ransomware_votes': ransomware_votes,
            'benign_votes': benign_votes,
            'final_decision': 'Ransomware' if ransomware_votes >= 2 else 'Benign'
        }
        
        return breakdown
    
    def _get_top_features(self, shap_values: np.ndarray, feature_values: np.ndarray, top_k: int) -> Dict:
        """Get top contributing features with explanations"""
        
        # Get absolute SHAP values for ranking
        abs_shap = np.abs(shap_values)
        
        # Get top k indices
        top_indices = np.argsort(abs_shap)[-top_k:][::-1]
        
        contributions = []
        
        for idx in top_indices:
            # Use feature name if available
            feature_name = f"Feature_{idx}"  # Default fallback
            
            if idx < len(self.feature_names):
                feature_name = self.feature_names[idx]
            
            contribution = {
                'feature_id': str(idx),
                'feature_name': feature_name,
                'feature_value': float(feature_values[idx]),
                'shap_value': float(shap_values[idx]),
                'abs_shap_value': float(abs_shap[idx]),
                'contribution_type': 'Increases Ransomware Risk' if shap_values[idx] > 0 else 'Decreases Ransomware Risk'
            }
            
            contributions.append(contribution)
        
        return {
            'top_features': contributions,
            'total_features': len(shap_values),
            'base_value': 0.0,  # SHAP base value
            'prediction_explanation': self._generate_text_explanation(contributions)
        }
    
    def _generate_text_explanation(self, contributions: List[Dict]) -> str:
        """Generate human-readable explanation"""
        
        if not contributions:
            return "No significant features found."
        
        # Separate positive and negative contributions
        positive_contribs = [c for c in contributions if c['shap_value'] > 0]
        negative_contribs = [c for c in contributions if c['shap_value'] < 0]
        
        explanation_parts = []
        
        if positive_contribs:
            top_positive = positive_contribs[0]
            explanation_parts.append(
                f"Primary ransomware indicator: {top_positive['feature_name']} "
                f"(contribution: +{top_positive['shap_value']:.3f})"
            )
        
        if negative_contribs:
            top_negative = negative_contribs[0]
            explanation_parts.append(
                f"Primary benign indicator: {top_negative['feature_name']} "
                f"(contribution: {top_negative['shap_value']:.3f})"
            )
        
        if len(positive_contribs) > 1:
            explanation_parts.append(
                f"Additional ransomware indicators: {len(positive_contribs)-1} features"
            )
        
        return " | ".join(explanation_parts)


def load_static_ensemble_explainer(models_dir: str = "models/static_ensemble", 
                                  feature_names_file: str = None,
                                  background_data: np.ndarray = None) -> StaticEnsembleXAIExplainer:
    """
    Convenience function to load and initialize static ensemble explainer
    
    Args:
        models_dir: Directory containing saved models
        feature_names_file: Path to feature names JSON
        background_data: Training data sample for explainers
        
    Returns:
        Initialized StaticEnsembleXAIExplainer
    """
    explainer = StaticEnsembleXAIExplainer(models_dir, feature_names_file)
    
    # Load models
    if not explainer.load_models():
        raise RuntimeError("Failed to load static ensemble models")
    
    # Create explainers if background data provided
    if background_data is not None:
        explainer.create_explainers(background_data)
    
    return explainer


# Example usage and testing
def test_static_ensemble_explainer():
    """Test the static ensemble explainer with sample data"""
    
    try:
        # Load explainer
        explainer = StaticEnsembleXAIExplainer(
            models_dir="models/static_ensemble",
            feature_names_file="models/static_ensemble/feature_names.json"
        )
        
        # Load models
        if not explainer.load_models():
            print("Failed to load models")
            return
        
        # Create sample background data (you would use real training data)
        # Assuming ~225 features for static analysis
        background_data = np.random.randint(0, 2, size=(100, 225))  # Binary features
        explainer.create_explainers(background_data)
        
        # Create sample features for explanation
        sample_features = np.random.randint(0, 2, size=225)  # Single sample
        
        # Get explanation
        explanation = explainer.explain_prediction(sample_features, top_k=10)
        
        print("Static Ensemble XAI Explanation:")
        print("=" * 50)
        
        # Print individual model results
        for model_name, result in explanation['individual_models'].items():
            if 'error' not in result:
                print(f"{model_name}: {result['prediction_label']} ({result['confidence']:.3f})")
        
        # Print ensemble result
        ensemble = explanation['ensemble']
        print(f"Ensemble: {ensemble['prediction_label']}")
        
        # Print top features
        features = explanation['feature_contributions']
        print(f"\nTop Contributing Features:")
        for feature in features['top_features'][:5]:
            print(f"- {feature['feature_name']}: {feature['shap_value']:.3f}")
        
        print(f"\nExplanation: {features['prediction_explanation']}")
        
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    test_static_ensemble_explainer()