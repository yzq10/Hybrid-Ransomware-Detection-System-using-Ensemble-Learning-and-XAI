"""
Fixed Enhanced Training Script
Proper cross-validation with model creation inside CV loop
"""

import pandas as pd
import numpy as np
import pickle
import logging
import time
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    classification_report, confusion_matrix
)

import xgboost as xgb
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier

import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FixedEnsembleTrainer:
    """Fixed trainer with proper cross-validation."""
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.svm_scaler = None
        
    def plot_confusion_matrix(self, cm, model_name, output_dir="models/temp/dynamic_ensemble"):
        """Plot and save confusion matrix visualization."""
        plt.figure(figsize=(8, 6))
        
        # Create heatmap
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Benign', 'Ransomware'],
                   yticklabels=['Benign', 'Ransomware'],
                   square=True, cbar_kws={'shrink': 0.8},
                   annot_kws={'size': 18})                   
        
        plt.title(f'{model_name} - Confusion Matrix', fontsize=22, fontweight='bold', pad=20)
        plt.xlabel('Predicted Label', fontsize=20)
        plt.ylabel('True Label', fontsize=20)

        # Make tick labels bigger
        plt.xticks(fontsize=16)  # ← X-axis tick labels (Benign/Ransomware)
        plt.yticks(fontsize=16)  # ← Y-axis tick labels (Benign/Ransomware)
        
        # Special formatting for ensemble
        if model_name == 'Ensemble':
            for spine in plt.gca().spines.values():
                spine.set_color('red')
                spine.set_linewidth(3)
        
        plt.tight_layout()
        
        # Save plot
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        plot_file = output_path / f"confusion_matrix_{model_name.lower()}.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.show()
        plt.close()
        
        logging.info(f"✅ Saved {model_name} confusion matrix: {plot_file}")
        return str(plot_file)
        
    def load_data(self, train_csv, test_csv):
        """Load training and test data with detailed analysis."""
        logging.info("="*50)
        logging.info("LOADING AND ANALYZING DATASETS")
        logging.info("="*50)
        
        # Load data
        start_time = time.time()
        self.train_df = pd.read_csv(train_csv)
        self.test_df = pd.read_csv(test_csv)
        load_time = time.time() - start_time
        
        logging.info(f"✓ Data loading completed in {load_time:.2f} seconds")
        logging.info(f"Training data shape: {self.train_df.shape}")
        logging.info(f"Test data shape: {self.test_df.shape}")
        
        # Identify columns
        metadata_cols = ['sample_id', 'sample_type', 'family_label', 'type_label']
        available_metadata = [col for col in metadata_cols if col in self.train_df.columns]
        feature_cols = [col for col in self.train_df.columns if col not in available_metadata]
        
        logging.info(f"Metadata columns found: {available_metadata}")
        logging.info(f"Feature columns: {len(feature_cols)}")
        
        # Prepare train data
        self.X_train = self.train_df[feature_cols]
        self.y_train = (self.train_df['family_label'] > 0).astype(int)
        
        # Prepare test data
        self.X_test = self.test_df[feature_cols]
        self.y_test = (self.test_df['family_label'] > 0).astype(int)
        
        # Detailed class distribution analysis
        logging.info("\n📊 DETAILED CLASS DISTRIBUTION ANALYSIS:")
        
        # Training set analysis
        train_benign = (self.y_train == 0).sum()
        train_ransomware = (self.y_train == 1).sum()
        train_total = len(self.y_train)
        train_ratio = train_ransomware / train_total * 100
        
        logging.info(f"Training Set:")
        logging.info(f"  - Benign: {train_benign:,} samples ({100-train_ratio:.1f}%)")
        logging.info(f"  - Ransomware: {train_ransomware:,} samples ({train_ratio:.1f}%)")
        logging.info(f"  - Total: {train_total:,} samples")
        logging.info(f"  - Class Ratio: {train_ransomware/train_benign:.3f} (R:B)")
        
        # Test set analysis
        test_benign = (self.y_test == 0).sum()
        test_ransomware = (self.y_test == 1).sum()
        test_total = len(self.y_test)
        test_ratio = test_ransomware / test_total * 100
        
        logging.info(f"Test Set:")
        logging.info(f"  - Benign: {test_benign:,} samples ({100-test_ratio:.1f}%)")
        logging.info(f"  - Ransomware: {test_ransomware:,} samples ({test_ratio:.1f}%)")
        logging.info(f"  - Total: {test_total:,} samples")
        logging.info(f"  - Class Ratio: {test_ransomware/test_benign:.3f} (R:B)")
        
        # Feature analysis
        logging.info(f"\n🔍 FEATURE ANALYSIS:")
        logging.info(f"  - Total features: {len(feature_cols)}")
        
        # Check feature sparsity
        train_sparsity = (self.X_train == 0).sum().sum() / (self.X_train.shape[0] * self.X_train.shape[1])
        test_sparsity = (self.X_test == 0).sum().sum() / (self.X_test.shape[0] * self.X_test.shape[1])
        
        logging.info(f"  - Training set sparsity: {train_sparsity:.1%} (zeros)")
        logging.info(f"  - Test set sparsity: {test_sparsity:.1%} (zeros)")
        logging.info(f"  - Feature value range: [{self.X_train.min().min()}, {self.X_train.max().max()}]")
        
        return feature_cols
    
    def create_fresh_models(self):
        """Create fresh model instances for each training run."""
        # Simple XGBoost
        xgb_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=8,
            random_state=self.random_state,
            eval_metric='logloss',
            verbosity=0,
            use_label_encoder=False
        )
        
        # Simple Random Forest
        rf_model = RandomForestClassifier(
            n_estimators=300,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        # Simple SVM
        svm_model = SVC(
            kernel='linear',
            probability=True,
            random_state=self.random_state
        )
        
        return {
            'XGBoost': xgb_model,
            'RandomForest': rf_model,
            'SVM': svm_model
        }
    
    def create_models(self):
        """Create ensemble models with detailed configuration."""
        logging.info("\n🤖 CREATING ENSEMBLE MODELS")
        logging.info("="*40)
        
        self.models = self.create_fresh_models()
        
        # Log model configurations
        logging.info("Model configurations:")
        logging.info(f"  XGBoost: {self.models['XGBoost'].n_estimators} trees, max_depth={self.models['XGBoost'].max_depth}")
        logging.info(f"  RandomForest: {self.models['RandomForest'].n_estimators} trees, n_jobs={self.models['RandomForest'].n_jobs}")
        logging.info(f"  SVM: {self.models['SVM'].kernel} kernel, probability={self.models['SVM'].probability}")
        logging.info(f"✓ Created {len(self.models)} models successfully")
    
    def train_and_evaluate(self, X_train, y_train, X_test, y_test):
        """Train models and evaluate with detailed reporting and error handling."""
        logging.info("\n🔥 TRAINING AND EVALUATION PHASE")
        logging.info("="*50)
        
        results = {}
        training_times = {}
        
        for name, model in self.models.items():
            logging.info(f"\n📈 Training {name}...")
            logging.info("-" * 30)
            
            try:
                start_time = time.time()
                
                if name == 'SVM':
                    # Scale for SVM
                    logging.info("  Scaling features for SVM...")
                    scaler = StandardScaler()
                    X_train_scaled = scaler.fit_transform(X_train)
                    X_test_scaled = scaler.transform(X_test)
                    
                    logging.info("  Fitting SVM model...")
                    model.fit(X_train_scaled, y_train)
                    
                    logging.info("  Making predictions...")
                    y_pred = model.predict(X_test_scaled)
                    y_proba = model.predict_proba(X_test_scaled)[:, 1]
                    
                    # Store scaler for final training
                    self.svm_scaler = scaler
                else:
                    # No scaling for tree models
                    logging.info(f"  Fitting {name} model...")
                    model.fit(X_train, y_train)
                    
                    logging.info("  Making predictions...")
                    y_pred = model.predict(X_test)
                    y_proba = model.predict_proba(X_test)[:, 1]
                
                training_time = time.time() - start_time
                training_times[name] = training_time
                
                # Calculate detailed metrics
                metrics = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, zero_division=0),
                    'recall': recall_score(y_test, y_pred, zero_division=0),
                    'f1': f1_score(y_test, y_pred, zero_division=0),
                    'auc': roc_auc_score(y_test, y_proba),
                    'training_time': training_time
                }
                
                # Generate detailed classification report
                class_report = classification_report(y_test, y_pred, 
                                                   target_names=['Benign', 'Ransomware'],
                                                   output_dict=True, zero_division=0)
                
                # Generate confusion matrix
                cm = confusion_matrix(y_test, y_pred)
                
                results[name] = {
                    'model': model,
                    'metrics': metrics,
                    'predictions': y_pred,
                    'probabilities': y_proba,
                    'classification_report': class_report,
                    'confusion_matrix': cm,
                    'success': True
                }
                
                # Detailed logging
                logging.info(f"  ✓ {name} training completed in {training_time:.2f} seconds")
                logging.info(f"  📊 Performance Metrics:")
                logging.info(f"     Accuracy:  {metrics['accuracy']:.4f}")
                logging.info(f"     Precision: {metrics['precision']:.4f}")
                logging.info(f"     Recall:    {metrics['recall']:.4f}")
                logging.info(f"     F1-Score:  {metrics['f1']:.4f}")
                logging.info(f"     AUC:       {metrics['auc']:.4f}")
                
                # Confusion matrix details
                tn, fp, fn, tp = cm.ravel()
                logging.info(f"  🎯 Confusion Matrix:")
                logging.info(f"     True Negatives (TN):  {tn}")
                logging.info(f"     False Positives (FP): {fp}")
                logging.info(f"     False Negatives (FN): {fn}")
                logging.info(f"     True Positives (TP):  {tp}")
                
                # Plot confusion matrix
                self.plot_confusion_matrix(cm, name)
                
                # Per-class performance
                logging.info(f"  📈 Per-Class Performance:")
                logging.info(f"     Benign    - Precision: {class_report['Benign']['precision']:.4f}, Recall: {class_report['Benign']['recall']:.4f}")
                logging.info(f"     Ransomware - Precision: {class_report['Ransomware']['precision']:.4f}, Recall: {class_report['Ransomware']['recall']:.4f}")
                
            except Exception as e:
                training_time = time.time() - start_time
                logging.error(f"  ✗ {name} training FAILED after {training_time:.2f} seconds")
                logging.error(f"  Error: {str(e)}")
                
                results[name] = {
                    'success': False,
                    'error': str(e),
                    'training_time': training_time
                }
                training_times[name] = training_time
        
        # Summary of training times
        logging.info(f"\n⏱️  TRAINING TIME SUMMARY:")
        total_time = sum(training_times.values())
        for name, time_taken in training_times.items():
            percentage = (time_taken / total_time) * 100 if total_time > 0 else 0
            logging.info(f"   {name}: {time_taken:.2f}s ({percentage:.1f}%)")
        logging.info(f"   Total: {total_time:.2f}s")
        
        return results
    
    def evaluate_ensemble(self, results, y_test):
        """Evaluate ensemble performance with detailed analysis."""
        logging.info("\n🎯 ENSEMBLE EVALUATION")
        logging.info("="*40)
        
        # Filter successful models only
        successful_results = {name: result for name, result in results.items() 
                            if result.get('success', False)}
        
        if len(successful_results) < 2:
            logging.error(f"❌ Insufficient models for ensemble: {len(successful_results)}/3 successful")
            logging.error("Need at least 2 models for ensemble prediction")
            return None
        
        logging.info(f"✓ Using {len(successful_results)}/3 models for ensemble")
        logging.info(f"  Successful models: {list(successful_results.keys())}")
        
        # Get predictions
        predictions = []
        probabilities = []
        model_names = []
        
        for name, result in successful_results.items():
            predictions.append(result['predictions'])
            probabilities.append(result['probabilities'])
            model_names.append(name)
        
        # Majority voting with detailed analysis
        ensemble_pred = []
        ensemble_proba = []
        voting_details = []
        
        for i in range(len(y_test)):
            votes = [pred[i] for pred in predictions]
            probas = [prob[i] for prob in probabilities]
            
            # Count votes
            ransomware_votes = sum(votes)
            benign_votes = len(votes) - ransomware_votes
            
            # Majority vote decision
            majority_vote = int(ransomware_votes > benign_votes)
            avg_proba = np.mean(probas)
            
            ensemble_pred.append(majority_vote)
            ensemble_proba.append(avg_proba)
            
            # Store voting details for analysis
            voting_details.append({
                'true_label': y_test.iloc[i] if hasattr(y_test, 'iloc') else y_test[i],
                'ransomware_votes': ransomware_votes,
                'benign_votes': benign_votes,
                'final_prediction': majority_vote,
                'avg_probability': avg_proba
            })
        
        # Calculate ensemble metrics
        ensemble_metrics = {
            'accuracy': accuracy_score(y_test, ensemble_pred),
            'precision': precision_score(y_test, ensemble_pred, zero_division=0),
            'recall': recall_score(y_test, ensemble_pred, zero_division=0),
            'f1': f1_score(y_test, ensemble_pred, zero_division=0),
            'auc': roc_auc_score(y_test, ensemble_proba)
        }
        
        # Generate detailed ensemble report
        ensemble_cm = confusion_matrix(y_test, ensemble_pred)
        
        # Voting analysis
        unanimous_decisions = sum(1 for vote in voting_details 
                                if vote['ransomware_votes'] == 0 or vote['ransomware_votes'] == len(model_names))
        majority_decisions = len(voting_details) - unanimous_decisions
        
        # Detailed logging
        logging.info("🏆 ENSEMBLE PERFORMANCE RESULTS:")
        logging.info(f"   Accuracy:  {ensemble_metrics['accuracy']:.4f}")
        logging.info(f"   Precision: {ensemble_metrics['precision']:.4f}")
        logging.info(f"   Recall:    {ensemble_metrics['recall']:.4f}")
        logging.info(f"   F1-Score:  {ensemble_metrics['f1']:.4f}")
        logging.info(f"   AUC:       {ensemble_metrics['auc']:.4f}")
        
        # Confusion matrix
        tn, fp, fn, tp = ensemble_cm.ravel()
        logging.info(f"\n🎯 ENSEMBLE CONFUSION MATRIX:")
        logging.info(f"   True Negatives (TN):  {tn}")
        logging.info(f"   False Positives (FP): {fp}")
        logging.info(f"   False Negatives (FN): {fn}")
        logging.info(f"   True Positives (TP):  {tp}")
        
        # Plot ensemble confusion matrix
        self.plot_confusion_matrix(ensemble_cm, "Ensemble")
        
        # Voting analysis
        logging.info(f"\n🗳️  VOTING ANALYSIS:")
        logging.info(f"   Unanimous decisions: {unanimous_decisions}/{len(voting_details)} ({unanimous_decisions/len(voting_details)*100:.1f}%)")
        logging.info(f"   Majority decisions:  {majority_decisions}/{len(voting_details)} ({majority_decisions/len(voting_details)*100:.1f}%)")
        
        # Model comparison
        logging.info(f"\n📊 INDIVIDUAL vs ENSEMBLE COMPARISON:")
        for name, result in successful_results.items():
            individual_f1 = result['metrics']['f1']
            improvement = ensemble_metrics['f1'] - individual_f1
            logging.info(f"   {name}: F1={individual_f1:.4f} → Ensemble: F1={ensemble_metrics['f1']:.4f} ({improvement:+.4f})")
        
        return {
            'metrics': ensemble_metrics,
            'predictions': ensemble_pred,
            'probabilities': ensemble_proba,
            'successful_models': list(successful_results.keys())
        }
    
    def perform_cross_validation(self, X, y, cv_folds=5):
        """Perform cross-validation analysis with proper model creation."""
        logging.info(f"🔄 Performing {cv_folds}-fold cross-validation...")
        
        # DEBUG: Check input data
        logging.info(f"DEBUG: Input X shape: {X.shape}, y shape: {y.shape}")
        logging.info(f"DEBUG: X type: {type(X)}, y type: {type(y)}")
        logging.info(f"DEBUG: y value counts: {y.value_counts().to_dict()}")
        
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
        
        # Model names for consistent results tracking
        model_names = ['XGBoost', 'RandomForest', 'SVM']
        
        # Initialize results for all metrics
        cv_results = {}
        for model_name in model_names:
            cv_results[model_name] = {
                'accuracy': [], 'precision': [], 'recall': [], 'f1': []
            }
        cv_results['Ensemble'] = {
            'accuracy': [], 'precision': [], 'recall': [], 'f1': []
        }
        
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            logging.info(f"\n   Fold {fold + 1}/{cv_folds}:")
            
            # DEBUG: Check fold data
            logging.info(f"   DEBUG: Train indices: {len(train_idx)}, Val indices: {len(val_idx)}")
            
            try:
                X_train_cv = X.iloc[train_idx]
                X_val_cv = X.iloc[val_idx]
                y_train_cv = y.iloc[train_idx]
                y_val_cv = y.iloc[val_idx]
                
                # DEBUG: Check fold shapes and distribution
                logging.info(f"   DEBUG: X_train_cv shape: {X_train_cv.shape}, X_val_cv shape: {X_val_cv.shape}")
                logging.info(f"   DEBUG: y_train_cv distribution: {y_train_cv.value_counts().to_dict()}")
                logging.info(f"   DEBUG: y_val_cv distribution: {y_val_cv.value_counts().to_dict()}")
                
            except Exception as e:
                logging.error(f"   ERROR: Data splitting failed: {str(e)}")
                continue
            
            # Create fresh models for this fold
            fold_models = self.create_fresh_models()
            
            # Store individual model results for ensemble calculation
            fold_model_results = {}
            
            logging.info(f"   DEBUG: Created {len(fold_models)} fresh models for fold {fold + 1}")
            logging.info(f"   DEBUG: Models to train: {list(fold_models.keys())}")

            # Train models for this fold
            for name, model in fold_models.items():
                logging.info(f"   Training {name}...")
                
                try:
                    if name == 'SVM':
                        # Scale for SVM
                        scaler = StandardScaler()
                        X_train_scaled = scaler.fit_transform(X_train_cv)
                        X_val_scaled = scaler.transform(X_val_cv)
                        
                        logging.info(f"   DEBUG: SVM about to fit...")
                        model.fit(X_train_scaled, y_train_cv)
                        logging.info(f"   DEBUG: SVM fit complete, making predictions...")
                        y_pred = model.predict(X_val_scaled)
                        y_proba = model.predict_proba(X_val_scaled)[:, 1]
                        
                    else:
                        logging.info(f"   DEBUG: {name} about to fit...")
                        model.fit(X_train_cv, y_train_cv)
                        logging.info(f"   DEBUG: {name} fit complete, making predictions...")
                        y_pred = model.predict(X_val_cv)
                        y_proba = model.predict_proba(X_val_cv)[:, 1]
                    
                    # Calculate and store metrics
                    accuracy = accuracy_score(y_val_cv, y_pred)
                    precision = precision_score(y_val_cv, y_pred, zero_division=0)
                    recall = recall_score(y_val_cv, y_pred, zero_division=0)
                    f1 = f1_score(y_val_cv, y_pred, zero_division=0)
                    
                    # Store results
                    cv_results[name]['accuracy'].append(accuracy)
                    cv_results[name]['precision'].append(precision)
                    cv_results[name]['recall'].append(recall)
                    cv_results[name]['f1'].append(f1)
                    
                    # Store for ensemble calculation
                    fold_model_results[name] = {
                        'predictions': y_pred,
                        'probabilities': y_proba
                    }
                    
                    logging.info(f"     {name}: Acc={accuracy:.4f}, Prec={precision:.4f}, Rec={recall:.4f}, F1={f1:.4f}")
                    
                except Exception as e:
                    logging.error(f"     {name}: FAILED - {str(e)}")
                    logging.error(f"     ERROR DETAILS: {type(e).__name__}")
                    import traceback
                    logging.error(f"     TRACEBACK: {traceback.format_exc()}")
                    
                    # Add zeros for failed models
                    cv_results[name]['accuracy'].append(0.0)
                    cv_results[name]['precision'].append(0.0)
                    cv_results[name]['recall'].append(0.0)
                    cv_results[name]['f1'].append(0.0)
            
            # Calculate ensemble metrics for this fold
            if len(fold_model_results) >= 2:
                try:
                    # Get ensemble predictions via majority voting
                    ensemble_pred = []
                    ensemble_proba = []
                    
                    for i in range(len(y_val_cv)):
                        votes = [result['predictions'][i] for result in fold_model_results.values()]
                        probas = [result['probabilities'][i] for result in fold_model_results.values()]
                        
                        majority_vote = int(sum(votes) >= len(votes) / 2)
                        avg_proba = np.mean(probas)
                        
                        ensemble_pred.append(majority_vote)
                        ensemble_proba.append(avg_proba)
                    
                    # Calculate ensemble metrics
                    ens_accuracy = accuracy_score(y_val_cv, ensemble_pred)
                    ens_precision = precision_score(y_val_cv, ensemble_pred, zero_division=0)
                    ens_recall = recall_score(y_val_cv, ensemble_pred, zero_division=0)
                    ens_f1 = f1_score(y_val_cv, ensemble_pred, zero_division=0)
                    
                    cv_results['Ensemble']['accuracy'].append(ens_accuracy)
                    cv_results['Ensemble']['precision'].append(ens_precision)
                    cv_results['Ensemble']['recall'].append(ens_recall)
                    cv_results['Ensemble']['f1'].append(ens_f1)
                    
                    logging.info(f"     Ensemble: Acc={ens_accuracy:.4f}, Prec={ens_precision:.4f}, Rec={ens_recall:.4f}, F1={ens_f1:.4f}")
                    
                except Exception as e:
                    logging.error(f"     Ensemble: FAILED - {str(e)}")
                    cv_results['Ensemble']['accuracy'].append(0.0)
                    cv_results['Ensemble']['precision'].append(0.0)
                    cv_results['Ensemble']['recall'].append(0.0)
                    cv_results['Ensemble']['f1'].append(0.0)
            else:
                logging.warning(f"     Ensemble: SKIPPED - Only {len(fold_model_results)} models succeeded")
                cv_results['Ensemble']['accuracy'].append(0.0)
                cv_results['Ensemble']['precision'].append(0.0)
                cv_results['Ensemble']['recall'].append(0.0)
                cv_results['Ensemble']['f1'].append(0.0)
        
        # Calculate CV statistics
        cv_summary = {}
        for model_name in cv_results.keys():
            cv_summary[model_name] = {}
            for metric in ['accuracy', 'precision', 'recall', 'f1']:
                scores = cv_results[model_name][metric]
                valid_scores = [s for s in scores if s > 0]
                
                if valid_scores:
                    cv_summary[model_name][metric] = {
                        'mean': np.mean(valid_scores),
                        'std': np.std(valid_scores),
                        'successful_folds': len(valid_scores)
                    }
                else:
                    cv_summary[model_name][metric] = {
                        'mean': 0.0, 'std': 0.0, 'successful_folds': 0
                    }
        
        # Calculate ensemble summary for backward compatibility
        ensemble_stats = cv_summary.get('Ensemble', {})
        ensemble_f1_stats = ensemble_stats.get('f1', {'mean': 0.0, 'std': 0.0})
        self._print_cv_results_table(cv_summary, cv_folds)
        
        return {
            'individual_models': cv_summary,
            'mean_f1': ensemble_f1_stats['mean'],
            'std_f1': ensemble_f1_stats['std'],
            'folds': cv_folds,
            'detailed_results': cv_summary
        }

    def _print_cv_results_table(self, cv_summary, cv_folds):
        """Print a formatted table of cross-validation results."""
        logging.info(f"\n📊 CROSS-VALIDATION RESULTS SUMMARY TABLE")
        logging.info("="*80)
        
        # Table header
        header = f"{'Model':<12} | {'Accuracy':<15} | {'Precision':<15} | {'Recall':<15} | {'F1-Score':<15} | {'Success':<8}"
        logging.info(header)
        logging.info("-" * len(header))
        
        # Individual models
        for model_name in ['XGBoost', 'RandomForest', 'SVM']:
            if model_name in cv_summary:
                stats = cv_summary[model_name]
                acc = stats['accuracy']
                prec = stats['precision']
                rec = stats['recall']
                f1 = stats['f1']
                
                row = (f"{model_name:<12} | "
                    f"{acc['mean']:.4f}±{acc['std']:.4f} | "
                    f"{prec['mean']:.4f}±{prec['std']:.4f} | "
                    f"{rec['mean']:.4f}±{rec['std']:.4f} | "
                    f"{f1['mean']:.4f}±{f1['std']:.4f} | "
                    f"{f1['successful_folds']}/{cv_folds}")
                logging.info(row)
        
        # Separator
        logging.info("-" * len(header))
        
        # Ensemble
        if 'Ensemble' in cv_summary:
            stats = cv_summary['Ensemble']
            acc = stats['accuracy']
            prec = stats['precision']
            rec = stats['recall']
            f1 = stats['f1']
            
            row = (f"{'Ensemble':<12} | "
                f"{acc['mean']:.4f}±{acc['std']:.4f} | "
                f"{prec['mean']:.4f}±{prec['std']:.4f} | "
                f"{rec['mean']:.4f}±{rec['std']:.4f} | "
                f"{f1['mean']:.4f}±{f1['std']:.4f} | "
                f"{f1['successful_folds']}/{cv_folds}")
            logging.info(row)
        
        logging.info("="*80)

    def train_final_models(self, X_combined, y_combined, feature_cols):
        """Train final models on combined dataset with detailed logging."""
        logging.info("\n" + "="*60)
        logging.info("🚀 TRAINING FINAL MODELS ON COMBINED DATASET")
        logging.info("="*60)
        
        # Dataset analysis
        full_benign = (y_combined == 0).sum()
        full_ransomware = (y_combined == 1).sum()
        full_total = len(y_combined)
        full_ratio = full_ransomware / full_total * 100
        
        logging.info(f"📊 COMBINED DATASET COMPOSITION:")
        logging.info(f"   Shape: {X_combined.shape}")
        logging.info(f"   Benign: {full_benign:,} samples ({100-full_ratio:.1f}%)")
        logging.info(f"   Ransomware: {full_ransomware:,} samples ({full_ratio:.1f}%)")
        logging.info(f"   Total: {full_total:,} samples")
        logging.info(f"   Class Ratio: {full_ransomware/full_benign:.3f} (R:B)")
        
        # Feature analysis
        logging.info(f"\n🔍 FEATURE ANALYSIS:")
        logging.info(f"  - Total features: {len(feature_cols)}")
        sparsity = (X_combined == 0).sum().sum() / (X_combined.shape[0] * X_combined.shape[1])
        logging.info(f"  - Combined dataset sparsity: {sparsity:.1%} (zeros)")
        logging.info(f"  - Feature value range: [{X_combined.min().min()}, {X_combined.max().max()}]")
        
        # Create fresh models for final training
        final_models = self.create_fresh_models()
        final_training_times = {}
        successful_final_models = {}
        
        for name, model in final_models.items():
            logging.info(f"\n🔄 Training final {name} on combined dataset...")
            start_time = time.time()
            
            try:
                if name == 'SVM':
                    # Scale for SVM
                    logging.info("   Scaling features for SVM...")
                    self.svm_scaler = StandardScaler()
                    X_combined_scaled = self.svm_scaler.fit_transform(X_combined)
                    
                    logging.info("   Fitting SVM on combined dataset...")
                    model.fit(X_combined_scaled, y_combined)
                    
                else:
                    logging.info(f"   Fitting {name} on combined dataset...")
                    model.fit(X_combined, y_combined)
                
                training_time = time.time() - start_time
                final_training_times[name] = training_time
                successful_final_models[name] = model
                
                logging.info(f"   ✅ {name} training completed in {training_time:.2f} seconds")
                
            except Exception as e:
                training_time = time.time() - start_time
                logging.error(f"   ❌ {name} final training FAILED after {training_time:.2f} seconds")
                logging.error(f"   Error: {str(e)}")
                final_training_times[name] = training_time
        
        # Summary
        logging.info(f"\n⏱️  FINAL TRAINING TIME SUMMARY:")
        total_final_time = sum(final_training_times.values())
        for name, time_taken in final_training_times.items():
            percentage = (time_taken / total_final_time) * 100 if total_final_time > 0 else 0
            status = "✅" if name in successful_final_models else "❌"
            logging.info(f"   {status} {name}: {time_taken:.2f}s ({percentage:.1f}%)")
        logging.info(f"   Total final training: {total_final_time:.2f}s")
        
        self.final_models = successful_final_models
        logging.info(f"\n🎯 Final models ready: {len(successful_final_models)}/{len(final_models)} successful")
        
        return successful_final_models
    
    def save_models(self, output_dir, experiment_name):
        """Save final models with detailed logging."""
        logging.info(f"\n💾 SAVING FINAL MODELS")
        logging.info("="*30)
        
        output_path = Path(output_dir) / experiment_name
        output_path.mkdir(parents=True, exist_ok=True)
        
        saved_models = []
        model_sizes = {}
        
        # Save final models
        for name, model in self.final_models.items():
            try:
                model_file = output_path / f"{name.lower()}_model.pkl"
                
                with open(model_file, 'wb') as f:
                    pickle.dump(model, f)
                
                # Get file size
                file_size = model_file.stat().st_size / (1024 * 1024)  # MB
                model_sizes[name] = file_size
                saved_models.append(name)
                
                logging.info(f"✅ Saved {name} model ({file_size:.2f} MB)")
                
            except Exception as e:
                logging.error(f"❌ Failed to save {name} model: {str(e)}")
        
        # Save SVM scaler
        if self.svm_scaler:
            try:
                scaler_file = output_path / "svm_scaler.pkl"
                with open(scaler_file, 'wb') as f:
                    pickle.dump(self.svm_scaler, f)
                
                scaler_size = scaler_file.stat().st_size / (1024 * 1024)  # MB
                logging.info(f"✅ Saved SVM scaler ({scaler_size:.2f} MB)")
                
            except Exception as e:
                logging.error(f"❌ Failed to save SVM scaler: {str(e)}")
        
        # Summary
        total_size = sum(model_sizes.values())
        logging.info(f"\n📦 MODEL SAVING SUMMARY:")
        logging.info(f"   Models saved: {len(saved_models)}/{len(self.final_models)}")
        logging.info(f"   Total size: {total_size:.2f} MB")
        logging.info(f"   Output directory: {output_path}")
        
        return output_path
    
    def run_complete_training(self, train_csv, test_csv, output_dir="models/temp/dynamic_ensemble", 
                            experiment_name="fixed_ensemble"):
        """Complete training workflow with proper cross-validation."""
        
        logging.info("🚀 STARTING COMPLETE TRAINING WORKFLOW")
        logging.info("="*70)
        
        overall_start_time = time.time()
        
        # Step 1: Load data
        logging.info("STEP 1: DATA LOADING AND ANALYSIS")
        feature_cols = self.load_data(train_csv, test_csv)
        
        # Step 2: Combine datasets for cross-validation
        logging.info("\n" + "="*50)
        logging.info("STEP 2: COMBINING DATASETS FOR CROSS-VALIDATION")
        logging.info("="*50)
        
        X_combined = pd.concat([self.X_train, self.X_test], ignore_index=True)
        y_combined = pd.concat([self.y_train, self.y_test], ignore_index=True)
        
        logging.info(f"Combined dataset shape: {X_combined.shape}")
        logging.info(f"Combined dataset labels shape: {y_combined.shape}")
        
        # Step 3: Cross-validation analysis on combined dataset
        logging.info("\n" + "="*50)
        logging.info("STEP 3: CROSS-VALIDATION ANALYSIS")
        logging.info("="*50)
        
        cv_results = self.perform_cross_validation(X_combined, y_combined)
        
        # Step 4: Create models and test on holdout set
        logging.info("\n" + "="*50)
        logging.info("STEP 4: TESTING PERFORMANCE ON HOLDOUT SET")
        logging.info("="*50)
        
        self.create_models()
        test_results = self.train_and_evaluate(self.X_train, self.y_train, self.X_test, self.y_test)
        ensemble_metrics = self.evaluate_ensemble(test_results, self.y_test)
        
        if ensemble_metrics is None:
            logging.error("❌ Cannot proceed without successful ensemble evaluation")
            return None
        
        # Step 5: Train final models on combined dataset
        logging.info("\nSTEP 5: TRAINING FINAL PRODUCTION MODELS")
        final_models = self.train_final_models(X_combined, y_combined, feature_cols)
        
        # Step 6: Save final models
        logging.info("\nSTEP 6: SAVING PRODUCTION MODELS")
        model_path = self.save_models(output_dir, experiment_name)
        
        # Final summary
        total_time = time.time() - overall_start_time
        
        logging.info("\n" + "="*70)
        logging.info("🎉 COMPLETE TRAINING WORKFLOW FINISHED!")
        logging.info("="*70)
        
        logging.info(f"📊 FINAL PERFORMANCE SUMMARY:")
        logging.info(f"   Cross-validation F1: {cv_results['mean_f1']:.4f} ± {cv_results['std_f1']:.4f}")
        logging.info(f"   Test set F1: {ensemble_metrics['metrics']['f1']:.4f}")
        logging.info(f"   Test set AUC: {ensemble_metrics['metrics']['auc']:.4f}")
        logging.info(f"   Successful models: {len(final_models)}/3")
        
        logging.info(f"\n⏱️  TOTAL WORKFLOW TIME: {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
        logging.info(f"💾 Models saved to: {model_path}")
        logging.info("🚀 Ready for production deployment!")
        
        return {
            'test_metrics': ensemble_metrics['metrics'],
            'cv_results': cv_results,
            'model_path': model_path,
            'successful_models': len(final_models),
            'total_time': total_time,
            'ensemble_details': ensemble_metrics
        }


def main():
    """Run the complete training workflow."""
    
    trainer = FixedEnsembleTrainer()
    
    results = trainer.run_complete_training(
        train_csv="MLRan_X_train_RFE.csv",
        test_csv="MLRan_X_test_RFE.csv",
        experiment_name="."
    )
    
    return results

if __name__ == "__main__":
    main()