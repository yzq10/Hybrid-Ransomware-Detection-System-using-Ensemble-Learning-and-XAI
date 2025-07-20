"""
Clean Dynamic XAI Explainer
ONLY responsible for explaining ML model predictions using SHAP
"""

import numpy as np
import pandas as pd
import shap
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class DynamicXAI:
    """
    Provides SHAP-based explanations for dynamic ransomware detection models
    """
    
    def __init__(self, models: Dict, feature_extractor):
        """
        Initialize XAI explainer
        
        Args:
            models: Dictionary of trained models {model_name: model}
            feature_extractor: Feature extractor instance for feature names
        """
        self.models = models
        self.feature_extractor = feature_extractor
        self.explainers = {}
        self.is_loaded = False
        self._initialize_explainers()
    
    def explain_prediction(self, features_df: pd.DataFrame, top_k: int = 10) -> Dict:
        """
        Generate SHAP explanations for the prediction
        
        Args:
            features_df: Feature DataFrame (single row)
            top_k: Number of top features to return
            
        Returns:
            Dictionary with explanations
        """
        if not self.is_loaded:
            logger.warning("XAI explainers not loaded, returning basic explanation")
            return self._basic_explanation(features_df)
        
        try:
            # Get SHAP values from each model
            model_explanations = {}
            
            for model_name, explainer in self.explainers.items():
                try:
                    # Try SHAP calculation with proper error handling
                    if model_name == 'svm':
                        # SVM needs special handling (scaled features)
                        try:
                            shap_values = explainer.shap_values(features_df.values)
                        except Exception as e1:
                            # Fallback: try with just the first row as 1D array
                            shap_values = explainer.shap_values(features_df.values[0])
                    else:
                        # XGBoost and RandomForest - try DataFrame first
                        try:
                            shap_values = explainer.shap_values(features_df)
                        except Exception as e1:
                            # Fallback: try with numpy array
                            try:
                                shap_values = explainer.shap_values(features_df.values)
                            except Exception as e2:
                                # Last resort: try with 1D array
                                shap_values = explainer.shap_values(features_df.values[0])
                    
                    # Handle different SHAP output formats
                    if isinstance(shap_values, list):
                        # Binary classification - take positive class
                        shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
                    
                    # Ensure we have the right array shape
                    if hasattr(shap_values, 'shape'):
                        if len(shap_values.shape) > 1:
                            # Take first row if 2D array
                            shap_values_1d = shap_values[0]
                        else:
                            # Already 1D
                            shap_values_1d = shap_values
                    else:
                        # Fallback for edge cases
                        shap_values_1d = np.array(shap_values).flatten()
                    
                    # Get feature contributions
                    feature_contributions = self._get_feature_contributions(
                        shap_values_1d, features_df.columns, top_k
                    )
                    
                    model_explanations[model_name] = {
                        'feature_contributions': feature_contributions,
                        'total_shap_impact': float(np.sum(np.abs(shap_values_1d)))
                    }
                    
                except Exception as e:
                    logger.warning(f"SHAP explanation failed for {model_name}: {e}")
                    model_explanations[model_name] = {'error': str(e)}
            
            # Combine explanations from all models
            combined_explanation = self._combine_model_explanations(
                model_explanations, features_df, top_k
            )
            
            return combined_explanation
            
        except Exception as e:
            logger.error(f"XAI explanation failed: {e}")
            return self._basic_explanation(features_df)
    
    def _initialize_explainers(self):
        """Initialize SHAP explainers for each model"""
        try:
            # Generate background data for SHAP
            background_data = self._generate_background_data()
            
            for model_name, model in self.models.items():
                try:
                    if model_name == 'svm':
                        # SVM explainer
                        self.explainers[model_name] = shap.KernelExplainer(
                            model.predict_proba, background_data[:50]  # Smaller sample for SVM
                        )
                    elif model_name == 'xgboost':
                        # XGBoost tree explainer
                        self.explainers[model_name] = shap.TreeExplainer(model)
                    elif model_name == 'randomforest':
                        # RandomForest tree explainer
                        self.explainers[model_name] = shap.TreeExplainer(model)
                    
                    logger.debug(f"Initialized SHAP explainer for {model_name}")
                    
                except Exception as e:
                    logger.warning(f"Failed to initialize explainer for {model_name}: {e}")
            
            if self.explainers:
                self.is_loaded = True
                logger.info(f"XAI explainers loaded: {list(self.explainers.keys())}")
            
        except Exception as e:
            logger.error(f"Failed to initialize XAI explainers: {e}")
    
    def _generate_background_data(self) -> np.ndarray:
        """Generate background data for SHAP explainers"""
        try:
            n_features = self.feature_extractor.get_feature_count()
            
            # Create diverse background data
            background_data = np.vstack([
                np.zeros((20, n_features)),  # All zeros
                np.ones((20, n_features)),   # All ones
                np.random.randint(0, 2, (60, n_features))  # Random binary
            ]).astype(float)
            
            logger.debug(f"Generated background data: {background_data.shape}")
            return background_data
            
        except Exception as e:
            logger.error(f"Failed to generate background data: {e}")
            # Fallback to 150 features
            return np.random.randint(0, 2, (100, 150)).astype(float)
    
    def _get_feature_contributions(self, shap_values: np.ndarray, 
                                 feature_columns: List[str], top_k: int) -> List[Dict]:
        """
        Get top contributing features with their SHAP values
        
        Args:
            shap_values: SHAP values array
            feature_columns: Feature column names
            top_k: Number of top features to return
            
        Returns:
            List of feature contributions sorted by importance
        """
        feature_contributions = []
        
        print(f"  DEBUG: shap_values shape: {shap_values.shape}")
        print(f"  DEBUG: feature_columns length: {len(feature_columns)}")
        
        # Ensure shap_values is 1D and matches feature_columns length
        if len(shap_values.shape) > 1:
            shap_values = shap_values.flatten()
        
        # If lengths don't match, take the minimum
        min_length = min(len(shap_values), len(feature_columns))
        
        for i in range(min_length):
            try:
                feature_id = feature_columns[i]
                shap_value = shap_values[i]
                
                # Convert numpy types to Python types safely
                if hasattr(shap_value, 'item'):
                    shap_value_float = float(shap_value.item())
                else:
                    shap_value_float = float(shap_value)
                
                feature_name = self.feature_extractor.feature_mapping.get(
                    int(feature_id), f"Feature_{feature_id}"
                )
                
                feature_contributions.append({
                    'feature_id': feature_id,
                    'feature_name': feature_name,
                    'shap_value': shap_value_float,
                    'abs_shap_value': abs(shap_value_float),
                    'contribution': 'positive' if shap_value_float > 0 else 'negative'
                })
                
            except Exception as e:
                print(f"  DEBUG: Error processing feature {i}: {e}")
                continue
        
        # Sort by absolute SHAP value (importance)
        feature_contributions.sort(key=lambda x: x['abs_shap_value'], reverse=True)
        
        return feature_contributions[:top_k]
    
    def _combine_model_explanations(self, model_explanations: Dict, 
                                  features_df: pd.DataFrame, top_k: int) -> Dict:
        """
        Combine explanations from all models into ensemble explanation
        
        Args:
            model_explanations: Individual model explanations
            features_df: Original features DataFrame
            top_k: Number of top features
            
        Returns:
            Combined explanation dictionary
        """
        # Collect all feature contributions
        all_contributions = {}
        
        for model_name, explanation in model_explanations.items():
            if 'error' not in explanation:
                for feature in explanation['feature_contributions']:
                    feature_id = feature['feature_id']
                    if feature_id not in all_contributions:
                        all_contributions[feature_id] = {
                            'feature_name': feature['feature_name'],
                            'shap_values': [],
                            'total_abs_impact': 0
                        }
                    
                    all_contributions[feature_id]['shap_values'].append(feature['shap_value'])
                    all_contributions[feature_id]['total_abs_impact'] += abs(feature['shap_value'])
        
        # Create ensemble feature ranking
        ensemble_features = []
        for feature_id, data in all_contributions.items():
            avg_shap = np.mean(data['shap_values']) if data['shap_values'] else 0
            ensemble_features.append({
                'feature_id': feature_id,
                'feature_name': data['feature_name'],
                'avg_shap_value': float(avg_shap),
                'total_impact': float(data['total_abs_impact']),
                'model_count': len(data['shap_values']),
                'contribution': 'positive' if avg_shap > 0 else 'negative'
            })
        
        # Sort by total impact
        ensemble_features.sort(key=lambda x: x['total_impact'], reverse=True)
        top_features = ensemble_features[:top_k]
        
        # Generate explanation text
        if top_features:
            top_feature = top_features[0]
            if top_feature['avg_shap_value'] > 0:
                explanation_text = f"The model predicts RANSOMWARE primarily due to '{top_feature['feature_name']}' and {len(top_features)-1} other suspicious behaviors."
            else:
                explanation_text = f"The model predicts BENIGN as '{top_feature['feature_name']}' and other features suggest normal behavior."
        else:
            explanation_text = "The model made a prediction based on the overall feature pattern."
        
        return {
            'model_explanations': model_explanations,
            'ensemble_explanation': {
                'top_features': top_features,
                'explanation_text': explanation_text,
                'total_features_analyzed': len(features_df.columns),
                'models_with_explanations': len([m for m in model_explanations.values() if 'error' not in m])
            }
        }
    
    def _basic_explanation(self, features_df: pd.DataFrame) -> Dict:
        """
        Generate basic explanation when SHAP is not available
        
        Args:
            features_df: Feature DataFrame
            
        Returns:
            Basic explanation dictionary
        """
        # Count active features
        active_features = []
        for col in features_df.columns:
            if features_df[col].iloc[0] == 1:
                feature_name = self.feature_extractor.feature_mapping.get(
                    int(col), f"Feature_{col}"
                )
                active_features.append({
                    'feature_id': col,
                    'feature_name': feature_name,
                    'value': 1
                })
        
        return {
            'model_explanations': {},
            'ensemble_explanation': {
                'top_features': active_features[:10],
                'explanation_text': f"Analysis based on {len(active_features)} detected behavioral features. SHAP explanations unavailable.",
                'total_features_analyzed': len(features_df.columns),
                'models_with_explanations': 0
            }
        }
    
    def get_explainer_info(self) -> Dict:
        """Get information about loaded explainers"""
        return {
            'is_loaded': self.is_loaded,
            'available_explainers': list(self.explainers.keys()),
            'explainer_count': len(self.explainers),
            'feature_count': self.feature_extractor.get_feature_count() if self.feature_extractor else 0
        }