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
```bash
git clone https://github.com/yourusername/hybrid-ransomware-detection.git
cd hybrid-ransomware-detection
```

#### 2. Environment Preparation
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
python --version
```

#### 3. Dependency Installation
```bash
pip install -r requirements.txt
pip list | grep -E "(Flask|scikit-learn|xgboost|pandas|numpy|shap|pefile|requests)"
```

#### 4. API Configuration
```bash
export VT_API_KEY="your_virustotal_api_key_here"
# Or create .env file:
echo "VT_API_KEY=your_virustotal_api_key_here" > .env
```

#### 5. Start Application
```bash
python app.py
```

## 🦆 Cuckoo Sandbox Setup

For full dynamic analysis capabilities, install Cuckoo Sandbox on a separate Linux machine.

### Installation Guide
Refer to the following link for complete installation instructions:
https://github.com/OpenSecureCo/Demos/blob/main/Cuckoo%20Install

### Update Application Config
```python
# In app.py
CUCKOO_API_URL = 'http://your-cuckoo-server:8090'
```

### Note
Without Cuckoo, the system will run in **static analysis only** mode.
