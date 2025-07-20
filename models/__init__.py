# This file makes the models directory a Python package
# You can add model loading utilities or configurations here if needed

import os

def get_model_path(model_name):
    """
    Get the full path to a model file
    
    Args:
        model_name (str): Name of the model file
        
    Returns:
        str: Full path to the model file
    """
    models_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(models_dir, model_name)

# Model file constants
RANSOMWARE_MODEL_FILE = "ransomware_detector_model.pkl"
RANSOMWARE_PREPROCESSOR_FILE = "ransomware_preprocessor.pkl"
DYNAMIC_RANSOMWARE_MODEL_FILE = "ransomware_rf_model.pkl"