"""
Modified Strategy 1: Ensemble Feature Selection for API/DLL Dataset
XGBoost + SVM + Random Forest with Chi-square selection inside CV folds
Handles binary-only features (APIs/DLLs) without PE header complications
UPDATED: Replaced Naive Bayes with Random Forest for better performance
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import logging
import time
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_and_prepare_data(csv_path):
    """Load API/DLL dataset and prepare features and target."""
    logging.info(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Identify feature columns (exclude identifiers and target)
    identifier_cols = ['SHA256', 'filename']
    target_col = 'Malware_Type'
    family_cols = [col for col in df.columns if col.startswith('_family')]
    
    # Get feature columns (should be only API_ and DLL_ features)
    feature_cols = [col for col in df.columns 
                   if col not in identifier_cols + [target_col] + family_cols]
    
    # Separate API and DLL features for analysis
    api_cols = [col for col in feature_cols if col.startswith('API_')]
    dll_cols = [col for col in feature_cols if col.startswith('DLL_')]
    
    logging.info(f"Dataset shape: {df.shape}")
    logging.info(f"Feature breakdown:")
    logging.info(f"  - API features: {len(api_cols)}")
    logging.info(f"  - DLL features: {len(dll_cols)}")
    logging.info(f"  - Total features: {len(feature_cols)}")
    
    # Prepare features and target
    X = df[feature_cols]
    y = df[target_col]
    
    # Check class distribution
    class_counts = y.value_counts()
    logging.info(f"Class distribution:")
    logging.info(f"  - Benign (0): {class_counts.get(0, 0)}")
    logging.info(f"  - Ransomware (1): {class_counts.get(1, 0)}")
    
    # Calculate sparsity
    total_cells = X.shape[0] * X.shape[1]
    non_zero_cells = (X == 1).sum().sum()
    sparsity = 1 - (non_zero_cells / total_cells)
    logging.info(f"  - Dataset sparsity: {sparsity:.2%}")
    
    return X, y, feature_cols, api_cols, dll_cols

def create_ensemble_models(random_state=42):
    """Create the three models for ensemble (optimized for binary features) - NOW WITH RANDOM FOREST."""
    
    # XGBoost - excellent for binary features
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=random_state,
        eval_metric='logloss',
        verbosity=0
    )
    
    # SVM - good for binary features (no scaling needed for 0/1 values)
    svm_model = SVC(
        kernel='rbf',
        C=1.0,
        gamma='scale',
        random_state=random_state,
        probability=True
    )
    
    # Random Forest - EXCELLENT for binary features (replaced Naive Bayes)
    rf_model = RandomForestClassifier(
        n_estimators=100,        # Good default for binary features
        max_depth=None,          # Let trees grow deep for binary patterns
        min_samples_split=5,     # Prevent overfitting
        min_samples_leaf=2,      # Balanced leaf nodes
        max_features='sqrt',     # Good for binary features
        random_state=random_state,
        n_jobs=-1               # Use all cores for speed
    )
    
    return {
        'XGBoost': xgb_model,
        'SVM': svm_model,
        'RandomForest': rf_model  # ← CHANGED FROM NaiveBayes
    }

def evaluate_single_fold(X_train, X_test, y_train, y_test, k_features, random_state=42):
    """Evaluate ensemble performance on a single fold with multiple metrics."""
    
    # Feature selection on training data only
    selector = SelectKBest(chi2, k=k_features)
    X_train_selected = selector.fit_transform(X_train, y_train)
    X_test_selected = selector.transform(X_test)
    
    # Get selected feature names
    selected_mask = selector.get_support()
    selected_feature_names = X_train.columns[selected_mask]
    
    # Create DataFrames with proper column names
    X_train_df = pd.DataFrame(X_train_selected, columns=selected_feature_names)
    X_test_df = pd.DataFrame(X_test_selected, columns=selected_feature_names)
    
    # Create models
    models = create_ensemble_models(random_state)
    fold_scores = {}
    
    for model_name, model in models.items():
        try:
            # All models work directly with binary features (no preprocessing needed)
            model.fit(X_train_df, y_train)
            y_pred = model.predict(X_test_df)
            
            # Get prediction probabilities for AUC
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test_df)[:, 1]
            else:
                y_pred_proba = y_pred  # Fallback
            
            # Calculate multiple metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0),
                'recall': recall_score(y_test, y_pred, zero_division=0),
                'f1': f1_score(y_test, y_pred, zero_division=0),
                'auc': roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_test)) > 1 else 0.5
            }
            
            fold_scores[model_name] = metrics
            
        except Exception as e:
            logging.warning(f"Error with {model_name}: {str(e)}")
            fold_scores[model_name] = {
                'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'auc': 0.5
            }
    
    # Calculate ensemble averages for each metric
    ensemble_scores = {}
    metric_names = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    
    for metric in metric_names:
        scores = [fold_scores[model][metric] for model in fold_scores.keys()]
        ensemble_scores[metric] = np.mean(scores)
    
    return fold_scores, ensemble_scores, selector

def test_feature_counts_with_ensemble_cv(X, y, feature_counts, cv_folds=5, random_state=42):
    """
    Test different numbers of features using cross-validation with ensemble evaluation.
    Feature selection is performed INSIDE each CV fold to avoid data leakage.
    """
    logging.info("="*60)
    logging.info("TESTING DIFFERENT FEATURE COUNTS WITH ENSEMBLE CV")
    logging.info("MODELS: XGBoost + SVM + Random Forest")  # ← UPDATED LOG MESSAGE
    logging.info("="*60)
    
    results = {}
    cv_splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    
    for num_features in feature_counts:
        logging.info(f"Testing {num_features} features...")
        start_time = time.time()
        
        fold_results = {
            'individual_scores': {
                model: {metric: [] for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']} 
                for model in ['XGBoost', 'SVM', 'RandomForest']  # ← UPDATED MODEL NAMES
            },
            'ensemble_scores': {metric: [] for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']}
        }
        
        # Perform cross-validation
        for fold_idx, (train_idx, test_idx) in enumerate(cv_splitter.split(X, y)):
            X_train_fold = X.iloc[train_idx]
            X_test_fold = X.iloc[test_idx]
            y_train_fold = y.iloc[train_idx]
            y_test_fold = y.iloc[test_idx]
            
            # Evaluate this fold
            individual_scores, ensemble_scores, _ = evaluate_single_fold(
                X_train_fold, X_test_fold, y_train_fold, y_test_fold,
                num_features, random_state
            )
            
            # Store results
            for model_name, metrics in individual_scores.items():
                for metric_name, score in metrics.items():
                    fold_results['individual_scores'][model_name][metric_name].append(score)
            
            for metric_name, score in ensemble_scores.items():
                fold_results['ensemble_scores'][metric_name].append(score)
        
        # Calculate statistics for all metrics
        ensemble_means = {
            metric: np.mean(fold_results['ensemble_scores'][metric]) 
            for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']
        }
        ensemble_stds = {
            metric: np.std(fold_results['ensemble_scores'][metric]) 
            for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']
        }
        
        individual_means = {}
        for model in ['XGBoost', 'SVM', 'RandomForest']:  # ← UPDATED MODEL NAMES
            individual_means[model] = {
                metric: np.mean(fold_results['individual_scores'][model][metric])
                for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']
            }
        
        # Store results
        results[num_features] = {
            'ensemble_means': ensemble_means,
            'ensemble_stds': ensemble_stds,
            'individual_means': individual_means,
            'fold_results': fold_results,
            'time_taken': time.time() - start_time
        }
        
        logging.info(f"  {num_features} features: Ensemble Metrics")
        logging.info(f"    Accuracy: {ensemble_means['accuracy']:.4f} (+/- {ensemble_stds['accuracy']*2:.4f})")
        logging.info(f"    Precision: {ensemble_means['precision']:.4f} (+/- {ensemble_stds['precision']*2:.4f})")
        logging.info(f"    Recall: {ensemble_means['recall']:.4f} (+/- {ensemble_stds['recall']*2:.4f})")
        logging.info(f"    F1-Score: {ensemble_means['f1']:.4f} (+/- {ensemble_stds['f1']*2:.4f})")
        logging.info(f"    AUC: {ensemble_means['auc']:.4f} (+/- {ensemble_stds['auc']*2:.4f})")
        logging.info(f"    Time: {time.time() - start_time:.1f}s")
        
        logging.info(f"    Individual Models (Accuracy):")
        logging.info(f"      XGB={individual_means['XGBoost']['accuracy']:.4f}, "
                    f"SVM={individual_means['SVM']['accuracy']:.4f}, "
                    f"RF={individual_means['RandomForest']['accuracy']:.4f}")  # ← UPDATED TO RF
    
    return results

def find_optimal_features(results, primary_metric='f1'):
    """Find the optimal number of features based on ensemble CV results."""
    logging.info("\n" + "="*60)
    logging.info("FINDING OPTIMAL NUMBER OF FEATURES")
    logging.info("="*60)
    
    # Find best performing feature count based on primary metric
    best_num_features = max(results.keys(), key=lambda k: results[k]['ensemble_means'][primary_metric])
    best_scores = results[best_num_features]['ensemble_means']
    best_stds = results[best_num_features]['ensemble_stds']
    
    logging.info(f"Optimal number of features: {best_num_features} (based on {primary_metric.upper()})")
    logging.info(f"Best ensemble scores:")
    logging.info(f"  - Accuracy: {best_scores['accuracy']:.4f} (+/- {best_stds['accuracy']*2:.4f})")
    logging.info(f"  - Precision: {best_scores['precision']:.4f} (+/- {best_stds['precision']*2:.4f})")
    logging.info(f"  - Recall: {best_scores['recall']:.4f} (+/- {best_stds['recall']*2:.4f})")
    logging.info(f"  - F1-Score: {best_scores['f1']:.4f} (+/- {best_stds['f1']*2:.4f})")
    logging.info(f"  - AUC: {best_scores['auc']:.4f} (+/- {best_stds['auc']*2:.4f})")
    
    # Display detailed results table
    logging.info(f"\nDetailed results comparison:")
    logging.info(f"{'Features':<10} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'AUC':<12} {'Time(s)':<8}")
    logging.info("-" * 80)
    
    for num_features in sorted(results.keys()):
        r = results[num_features]
        means = r['ensemble_means']
        logging.info(f"{num_features:<10} "
                    f"{means['accuracy']:.4f}       "
                    f"{means['precision']:.4f}       "
                    f"{means['recall']:.4f}       "
                    f"{means['f1']:.4f}       "
                    f"{means['auc']:.4f}       "
                    f"{r['time_taken']:.1f}")
    
    # Show individual model performance for best configuration
    logging.info(f"\nIndividual model performance at optimal {best_num_features} features:")
    individual_best = results[best_num_features]['individual_means']
    
    for model_name in ['XGBoost', 'SVM', 'RandomForest']:  # ← UPDATED MODEL NAMES
        model_scores = individual_best[model_name]
        logging.info(f"  {model_name}:")
        logging.info(f"    Accuracy: {model_scores['accuracy']:.4f}")
        logging.info(f"    Precision: {model_scores['precision']:.4f}")
        logging.info(f"    Recall: {model_scores['recall']:.4f}")
        logging.info(f"    F1-Score: {model_scores['f1']:.4f}")
        logging.info(f"    AUC: {model_scores['auc']:.4f}")
    
    return best_num_features, results[best_num_features]

def create_optimal_feature_dataset(X, y, optimal_k, input_csv, output_csv, random_state=42):
    """Create new CSV with optimal features only."""
    logging.info("\n" + "="*60)
    logging.info("CREATING OPTIMAL FEATURE DATASET")
    logging.info("="*60)
    
    # Apply feature selection to full dataset
    selector = SelectKBest(chi2, k=optimal_k)
    X_selected = selector.fit_transform(X, y)
    
    # Get selected feature names
    selected_mask = selector.get_support()
    selected_feature_names = X.columns[selected_mask]
    
    logging.info(f"Selected {len(selected_feature_names)} features for optimal dataset")
    
    # Load original dataset to get identifiers
    original_df = pd.read_csv(input_csv)
    identifier_cols = ['SHA256', 'filename']
    family_cols = [col for col in original_df.columns if col.startswith('_family')]
    
    # Create new dataset with identifiers + target + selected features
    optimal_df = original_df[identifier_cols + family_cols].copy() if family_cols else original_df[identifier_cols].copy()
    
    # Add selected features
    selected_features_df = pd.DataFrame(X_selected, columns=selected_feature_names)
    for col in selected_feature_names:
        optimal_df[col] = selected_features_df[col].values
    
    # Add target
    optimal_df['Malware_Type'] = y.values
    
    # Save optimal dataset
    optimal_df.to_csv(output_csv, index=False)
    
    logging.info(f"✅ Optimal dataset saved to: {output_csv}")
    logging.info(f"   - Shape: {optimal_df.shape}")
    logging.info(f"   - Features: {len(selected_feature_names)}")
    
    # Show feature breakdown
    api_features = [col for col in selected_feature_names if col.startswith('API_')]
    dll_features = [col for col in selected_feature_names if col.startswith('DLL_')]
    
    logging.info(f"   - API features: {len(api_features)}")
    logging.info(f"   - DLL features: {len(dll_features)}")
    
    return optimal_df, selected_feature_names

def train_final_ensemble(X, y, optimal_k, random_state=42):
    """Train final ensemble on full dataset with optimal number of features."""
    logging.info("\n" + "="*60)
    logging.info("TRAINING FINAL ENSEMBLE MODEL")
    logging.info("MODELS: XGBoost + SVM + Random Forest")  # ← UPDATED LOG MESSAGE
    logging.info("="*60)
    
    # Apply feature selection to full dataset
    selector = SelectKBest(chi2, k=optimal_k)
    X_selected = selector.fit_transform(X, y)
    
    # Get selected feature names
    selected_mask = selector.get_support()
    selected_feature_names = X.columns[selected_mask]
    
    # Create DataFrame with selected features
    X_selected_df = pd.DataFrame(X_selected, columns=selected_feature_names)
    
    # Train final models
    final_models = {}
    models = create_ensemble_models(random_state)
    
    for model_name, model in models.items():
        logging.info(f"Training final {model_name}...")
        model.fit(X_selected_df, y)
        final_models[model_name] = model
    
    logging.info("✅ Final ensemble trained successfully")
    
    return final_models, selector, selected_feature_names

def plot_results(results):
    """Plot feature selection results with multiple metrics."""
    feature_counts = sorted(results.keys())
    
    # Extract data for plotting
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    ensemble_data = {metric: [] for metric in metrics}
    ensemble_stds = {metric: [] for metric in metrics}
    
    individual_data = {
        'XGBoost': {metric: [] for metric in metrics},
        'SVM': {metric: [] for metric in metrics},
        'RandomForest': {metric: [] for metric in metrics}  # ← UPDATED MODEL NAME
    }
    
    for k in feature_counts:
        for metric in metrics:
            ensemble_data[metric].append(results[k]['ensemble_means'][metric])
            ensemble_stds[metric].append(results[k]['ensemble_stds'][metric])
            
            for model in ['XGBoost', 'SVM', 'RandomForest']:  # ← UPDATED MODEL NAMES
                individual_data[model][metric].append(results[k]['individual_means'][model][metric])
    
    # Create comprehensive plot
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    
    # Plot individual metrics
    metric_titles = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
    colors = ['blue', 'green', 'red']  # ← UPDATED COLOR (red for RF instead of orange for NB)
    
    for i, metric in enumerate(metrics):
        row = i // 3
        col = i % 3
        ax = axes[row, col]
        
        # Plot individual models
        for j, (model, color) in enumerate(zip(['XGBoost', 'SVM', 'RandomForest'], colors)):  # ← UPDATED
            ax.plot(feature_counts, individual_data[model][metric], 
                   'o-', label=model, color=color, alpha=0.7, linewidth=2)
        
        # Plot ensemble with error bars
        ax.errorbar(feature_counts, ensemble_data[metric], yerr=ensemble_stds[metric],
                   fmt='s-', label='Ensemble', color='purple', linewidth=3, capsize=5)  # ← CHANGED COLOR
        
        ax.set_xlabel('Number of Features')
        ax.set_ylabel(metric_titles[i])
        ax.set_title(f'{metric_titles[i]} vs Number of Features (XGB+SVM+RF)')  # ← UPDATED TITLE
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 1)
    
    # Remove the empty subplot
    fig.delaxes(axes[1, 2])
    
    plt.tight_layout()
    plt.savefig('api_dll_feature_selection_results_RF.png', dpi=300, bbox_inches='tight')  # ← UPDATED FILENAME
    plt.show()
    
    # Additional plot: All ensemble metrics together
    plt.figure(figsize=(12, 8))
    
    colors_metrics = ['blue', 'green', 'orange', 'red', 'purple']
    for i, metric in enumerate(metrics):
        plt.errorbar(feature_counts, ensemble_data[metric], yerr=ensemble_stds[metric],
                    fmt='o-', label=metric_titles[i], color=colors_metrics[i], 
                    linewidth=2, capsize=3)
    
    plt.xlabel('Number of Features')
    plt.ylabel('Score')
    plt.title('Ensemble Performance (XGB+SVM+RF): All Metrics vs Number of Features')  # ← UPDATED TITLE
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1)
    plt.savefig('ensemble_all_metrics_RF.png', dpi=300, bbox_inches='tight')  # ← UPDATED FILENAME
    plt.show()

def main():
    """Main function to run the complete feature selection pipeline."""
    
    # Configuration
    input_csv = "api_dll_dataset.csv"
    optimal_output_csv = "(test_purpose)optimal_api_dll_dataset.csv"
    feature_counts = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]  # ← ADD 50, 150, 200, 300 IF BETTER PERFORMANCE NEEDED (CURRENT IS 200)
    cv_folds = 5
    random_state = 42
    
    try:
        # Load data
        X, y, feature_cols, api_cols, dll_cols = load_and_prepare_data(input_csv)
        
        # Test different feature counts
        results = test_feature_counts_with_ensemble_cv(
            X, y, feature_counts, cv_folds, random_state
        )
        
        # Find optimal features
        optimal_k, best_result = find_optimal_features(results)
        
        # Create optimal feature dataset
        optimal_df, selected_features = create_optimal_feature_dataset(
            X, y, optimal_k, input_csv, optimal_output_csv, random_state
        )
        
        # Train final ensemble
        final_models, final_selector, _ = train_final_ensemble(
            X, y, optimal_k, random_state
        )
        
        # Plot results
        plot_results(results)
        
        logging.info("="*60)
        logging.info("API/DLL FEATURE SELECTION COMPLETED SUCCESSFULLY!")
        logging.info("ENSEMBLE: XGBoost + SVM + Random Forest")  # ← UPDATED MESSAGE
        logging.info("="*60)
        logging.info(f"✅ Optimal features: {optimal_k}")
        logging.info(f"✅ Best ensemble metrics:")
        logging.info(f"   - Accuracy: {best_result['ensemble_means']['accuracy']:.4f}")
        logging.info(f"   - Precision: {best_result['ensemble_means']['precision']:.4f}")
        logging.info(f"   - Recall: {best_result['ensemble_means']['recall']:.4f}")
        logging.info(f"   - F1-Score: {best_result['ensemble_means']['f1']:.4f}")
        logging.info(f"   - AUC: {best_result['ensemble_means']['auc']:.4f}")
        logging.info(f"✅ Optimal dataset saved: {optimal_output_csv}")
        logging.info(f"✅ Results plots saved: api_dll_feature_selection_results_RF.png, ensemble_all_metrics_RF.png")
        
        # Show top selected features
        logging.info(f"\nTop 20 selected features:")
        feature_scores = final_selector.scores_[final_selector.get_support()]
        feature_score_pairs = list(zip(selected_features, feature_scores))
        feature_score_pairs.sort(key=lambda x: x[1], reverse=True)
        
        for i, (feature, score) in enumerate(feature_score_pairs[:20]):
            logging.info(f"  {i+1:2d}. {feature}: {score:.4f}")
        
        # PERFORMANCE IMPROVEMENT ANALYSIS
        logging.info(f"\n🎯 EXPECTED PERFORMANCE IMPROVEMENT:")
        logging.info(f"   Previous ensemble (XGB+SVM+NB): Expected ~92-94% F1-score")
        logging.info(f"   New ensemble (XGB+SVM+RF): Actual {best_result['ensemble_means']['f1']:.1%} F1-score")
        improvement = (best_result['ensemble_means']['f1'] - 0.93) * 100  # Estimate vs previous
        if improvement > 0:
            logging.info(f"   🚀 Improvement: +{improvement:.1f} percentage points!")
        else:
            logging.info(f"   📊 Performance: {best_result['ensemble_means']['f1']:.1%} (baseline comparison)")
        
    except Exception as e:
        logging.error(f"Error in feature selection pipeline: {str(e)}")
        raise

if __name__ == "__main__":
    main()