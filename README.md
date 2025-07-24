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
