# Hybrid Ransomware Detection System

A comprehensive Windows malware detection system that combines static analysis, dynamic behavioral analysis, and explainable AI for accurate ransomware detection with detailed explanations.

## 🚀 Features

### Multi-Stage Analysis Pipeline
- **Signature Validation**: VirusTotal API integration for known threat detection
- **Static Analysis**: PE header analysis, API calls, and DLL imports extraction
- **Dynamic Analysis**: Cuckoo Sandbox integration for behavioral analysis
- **Explainable AI**: SHAP-based explanations for model predictions

### Advanced Machine Learning
- **Ensemble Learning**: XGBoost, Random Forest, and SVM models working together
- **Hard Voting Classification**: Majority voting for robust predictions
- **Feature Engineering**: 487 carefully selected features through RFE (Recursive Feature Elimination)
- **Confidence Scoring**: Probability-based confidence assessment

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10/11 and Linux (for Cuckoo Sandbox)
- **RAM**: Minimum 8GB, recommended 16GB+
- **Storage**: 10GB+ free space for models and temporary files
- **Network**: Internet connection for VirusTotal API
- **Python**: 3.8+ (recommended 3.9+)

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+ installed on your system
- Git installed
- Internet connection for package downloads
- VirusTotal API key (free account available)

### Step-by-Step Installation

#### 1. Repository Setup
- Clone the repository from GitHub
- Navigate to the project directory

#### 2. Environment Preparation
- Create a Python virtual environment
- Activate the virtual environment
- Verify Python version compatibility

#### 3. Dependency Installation
- Install all required Python packages using pip
- Verify successful installation of core libraries:
  - Flask (web framework)
  - scikit-learn (machine learning)
  - XGBoost (gradient boosting)
  - pandas (data manipulation)
  - numpy (numerical computing)
  - SHAP (explainable AI)
  - pefile (PE file analysis)
  - requests (API communication)

#### 4. API Configuration
- Obtain VirusTotal API key
- Configure API key as environment variable
- Set security mode preferences
- Test API connectivity

#### 5. Start Application
```bash
python app.py
