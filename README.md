# Hybrid Ransomware Detection System using Ensemble Learning and XAI

A comprehensive Windows ransomware detection system that combines static analysis, dynamic behavioral analysis, ensemble learnin and explainable AI for accurate ransomware detection with detailed explanations.

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

## 📖 Usage

The system offers flexible analysis modes to suit different security requirements and environments:

### 🔄 Full 3-Stage Pipeline (Recommended)
Complete analysis with maximum accuracy and detailed explanations:
- **Stage 1**: Signature Analysis (VirusTotal)
- **Stage 2**: Static Analysis (PE headers, APIs, ML models)
- **Stage 3**: Dynamic Analysis (Cuckoo Sandbox behavioral analysis)

```bash
# Access via web interface
http://localhost:5000

# Upload files and select "Full Analysis"
# Results include ensemble predictions, confidence scores, and XAI explanations
```

### 🎯 Individual Stage Analysis
For targeted analysis or when specific components are unavailable:

#### Signature Analysis Only
Quick threat intelligence lookup for known malware:
- Fast detection of known ransomware families
- Minimal system resources required
- Immediate results from VirusTotal database

#### Static Analysis Only  
In-depth file structure analysis without execution:
- PE header analysis and API call extraction
- Machine learning ensemble predictions
- SHAP-based feature importance explanations
- Suitable for air-gapped environments

#### Dynamic Analysis Only
Behavioral analysis in controlled sandbox environment:
- Real-time malware behavior monitoring
- Network traffic and file system activity tracking
- Registry modifications and process creation analysis

## 🏗️ System Architecture
* **Frontend**: HTML, CSS, JavaScript
* **Backend**: Python Flask API
* **Database**: SQLite / MySQL
* **Machine Learning**: Ensemble Models
  - **XGBoost**: Gradient boosting classifier
  - **Random Forest**: Tree-based ensemble model
  - **SVM**: Support Vector Machine with preprocessing
  - **SHAP**: Explainable AI for model interpretability
* **External APIs**:
  - **VirusTotal API**: Signature-based threat detection
  - **Cuckoo Sandbox**: Dynamic behavioral analysis

## 🤝 Contributing
This project was developed as a Final Year Project (FYP) demonstrating the practical implementation of hybrid ransomware detection using multi-stage analysis, ensemble learning and explainable AI for cybersecurity applications.

## 📄 License
This project is for educational and research purposes.
