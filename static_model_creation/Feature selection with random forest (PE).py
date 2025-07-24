"""
Strategy 1: PE Header Feature Selection using ANOVA F-test
XGBoost + SVM + Random Forest with ANOVA selection inside CV folds
Handles numerical PE header features (52 features)
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
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
    """Load PE headers dataset and prepare features and target."""
    logging.info(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Identify feature columns (exclude identifiers and target)
    identifier_cols = ['SHA256', 'filename']
    target_col = 'Malware_Type'
    family_cols = [col for col in df.columns if col.startswith('_family')]
    
    # Get PE header feature columns (numerical features)
    pe_header_cols = [
        'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 
        'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 
        'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'Machine', 'NumberOfSections', 
        'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 
        'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 
        'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 
        'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment', 
        'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 
        'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 
        'MinorSubsystemVersion', 'Reserved1', 'SizeOfImage', 'SizeOfHeaders', 
        'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 
        'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes'
    ]
    
    # Get actual PE header columns that exist in the dataset
    existing_pe_cols = [col for col in pe_header_cols if col in df.columns]
    
    logging.info(f"Dataset shape: {df.shape}")
    logging.info(f"PE header features found: {len(existing_pe_cols)}")
    logging.info(f"Expected PE features: {len(pe_header_cols)}")
    
    if len(existing_pe_cols) != len(pe_header_cols):
        missing_cols = set(pe_header_cols) - set(existing_pe_cols)
        logging.warning(f"Missing PE columns: {missing_cols}")
    
    # Prepare features and target
    X = df[existing_pe_cols]
    y = df[target_col]
    
    # Check class distribution
    class_counts = y.value_counts()
    logging.info(f"Class distribution:")
    logging.info(f"  - Benign (0): {class_counts.get(0, 0)}")
    logging.info(f"  - Ransomware (1): {class_counts.get(1, 0)}")
    
    # Check for any missing values
    missing_values = X.isnull().sum().sum()
    if missing_values > 0:
        logging.warning(f"Found {missing_values} missing values in PE headers")
        X = X.fillna(0)  # Fill with 0 if any missing values
    
    # Display basic statistics
    logging.info(f"PE header feature statistics:")
    logging.info(f"  - Mean values range: {X.mean().min():.2f} to {X.mean().max():.2e}")
    logging.info(f"  - Std values range: {X.std().min():.2f} to {X.std().max():.2e}")
    
    return X, y, existing_pe_cols

def create_ensemble_models(random_state=42):
    """Create the three models for ensemble (optimized for numerical features)."""
    
    # XGBoost - excellent for numerical features
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
    
    # SVM - needs scaling for numerical features
    svm_model = SVC(
        kernel='rbf',
        C=1.0,
        gamma='scale',
        random_state=random_state,
        probability=True
    )
    
    # Random Forest - excellent for numerical features, handles mixed scales well
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=10,
        min_samples_leaf=4,
        random_state=random_state,
        n_jobs=-1
    )
    
    return {
        'XGBoost': xgb_model,
        'SVM': svm_model,
        'RandomForest': rf_model
    }

def evaluate_single_fold(X_train, X_test, y_train, y_test, k_features, random_state=42):
    """Evaluate ensemble performance on a single fold with multiple metrics."""
    
    # Feature selection on training data only using ANOVA F-test
    selector = SelectKBest(f_classif, k=k_features)
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
            if model_name == 'SVM':
                # SVM needs scaling for numerical features
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train_df)
                X_test_scaled = scaler.transform(X_test_df)
                
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
                
            else:
                # XGBoost and Random Forest work directly with numerical features
                model.fit(X_train_df, y_train)
                y_pred = model.predict(X_test_df)
                
                if hasattr(model, 'predict_proba'):
                    y_pred_proba = model.predict_proba(X_test_df)[:, 1]
                else:
                    y_pred_proba = y_pred
            
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
    Test different numbers of PE header features using cross-validation with ensemble evaluation.
    Feature selection is performed INSIDE each CV fold to avoid data leakage.
    """
    logging.info("="*60)
    logging.info("TESTING DIFFERENT PE HEADER FEATURE COUNTS WITH ENSEMBLE CV")
    logging.info("="*60)
    
    results = {}
    cv_splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    
    for num_features in feature_counts:
        if num_features > X.shape[1]:
            logging.warning(f"Skipping {num_features} features (only {X.shape[1]} available)")
            continue
            
        logging.info(f"Testing {num_features} features...")
        start_time = time.time()
        
        fold_results = {
            'individual_scores': {
                model: {metric: [] for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']} 
                for model in ['XGBoost', 'SVM', 'RandomForest']
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
        for model in ['XGBoost', 'SVM', 'RandomForest']:
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
                    f"RF={individual_means['RandomForest']['accuracy']:.4f}")
    
    return results

def find_optimal_features(results, primary_metric='f1'):
    """Find the optimal number of features based on ensemble CV results."""
    logging.info("\n" + "="*60)
    logging.info("FINDING OPTIMAL NUMBER OF PE HEADER FEATURES")
    logging.info("="*60)
    
    # Find best performing feature count based on primary metric
    best_num_features = max(results.keys(), key=lambda k: results[k]['ensemble_means'][primary_metric])
    best_scores = results[best_num_features]['ensemble_means']
    best_stds = results[best_num_features]['ensemble_stds']
    
    logging.info(f"Optimal number of PE features: {best_num_features} (based on {primary_metric.upper()})")
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
    
    for model_name in ['XGBoost', 'SVM', 'RandomForest']:
        model_scores = individual_best[model_name]
        logging.info(f"  {model_name}:")
        logging.info(f"    Accuracy: {model_scores['accuracy']:.4f}")
        logging.info(f"    Precision: {model_scores['precision']:.4f}")
        logging.info(f"    Recall: {model_scores['recall']:.4f}")
        logging.info(f"    F1-Score: {model_scores['f1']:.4f}")
        logging.info(f"    AUC: {model_scores['auc']:.4f}")
    
    return best_num_features, results[best_num_features]

def create_optimal_feature_dataset(X, y, optimal_k, input_csv, output_csv, random_state=42):
    """Create new CSV with optimal PE header features only."""
    logging.info("\n" + "="*60)
    logging.info("CREATING OPTIMAL PE HEADER FEATURE DATASET")
    logging.info("="*60)
    
    # Apply feature selection to full dataset
    selector = SelectKBest(f_classif, k=optimal_k)
    X_selected = selector.fit_transform(X, y)
    
    # Get selected feature names
    selected_mask = selector.get_support()
    selected_feature_names = X.columns[selected_mask]
    
    logging.info(f"Selected {len(selected_feature_names)} PE header features for optimal dataset")
    
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
    
    logging.info(f"✅ Optimal PE header dataset saved to: {output_csv}")
    logging.info(f"   - Shape: {optimal_df.shape}")
    logging.info(f"   - Selected PE features: {len(selected_feature_names)}")
    
    return optimal_df, selected_feature_names

def train_final_ensemble(X, y, optimal_k, random_state=42):
    """Train final ensemble on full dataset with optimal number of PE header features."""
    logging.info("\n" + "="*60)
    logging.info("TRAINING FINAL PE HEADER ENSEMBLE MODEL")
    logging.info("="*60)
    
    # Apply feature selection to full dataset
    selector = SelectKBest(f_classif, k=optimal_k)
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
        
        if model_name == 'SVM':
            # SVM needs scaling for numerical features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_selected_df)
            model.fit(X_scaled, y)
            final_models[model_name] = {
                'model': model,
                'scaler': scaler
            }
        else:
            # XGBoost and Random Forest
            model.fit(X_selected_df, y)
            final_models[model_name] = {
                'model': model,
                'scaler': None
            }
    
    logging.info("✅ Final PE header ensemble trained successfully")
    
    return final_models, selector, selected_feature_names

def plot_results(results):
    """Plot PE header feature selection results with multiple metrics."""
    feature_counts = sorted(results.keys())
    
    # Extract data for plotting
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    ensemble_data = {metric: [] for metric in metrics}
    ensemble_stds = {metric: [] for metric in metrics}
    
    individual_data = {
        'XGBoost': {metric: [] for metric in metrics},
        'SVM': {metric: [] for metric in metrics},
        'RandomForest': {metric: [] for metric in metrics}
    }
    
    for k in feature_counts:
        for metric in metrics:
            ensemble_data[metric].append(results[k]['ensemble_means'][metric])
            ensemble_stds[metric].append(results[k]['ensemble_stds'][metric])
            
            for model in ['XGBoost', 'SVM', 'RandomForest']:
                individual_data[model][metric].append(results[k]['individual_means'][model][metric])
    
    # Create comprehensive plot
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    
    # Plot individual metrics
    metric_titles = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
    colors = ['blue', 'green', 'orange']
    
    for i, metric in enumerate(metrics):
        row = i // 3
        col = i % 3
        ax = axes[row, col]
        
        # Plot individual models
        for j, (model, color) in enumerate(zip(['XGBoost', 'SVM', 'RandomForest'], colors)):
            ax.plot(feature_counts, individual_data[model][metric], 
                   'o-', label=model, color=color, alpha=0.7, linewidth=2)
        
        # Plot ensemble with error bars
        ax.errorbar(feature_counts, ensemble_data[metric], yerr=ensemble_stds[metric],
                   fmt='s-', label='Ensemble', color='red', linewidth=3, capsize=5)
        
        ax.set_xlabel('Number of PE Header Features')
        ax.set_ylabel(metric_titles[i])
        ax.set_title(f'{metric_titles[i]} vs Number of PE Header Features')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 1)
    
    # Remove the empty subplot
    fig.delaxes(axes[1, 2])
    
    plt.tight_layout()
    plt.savefig('pe_header_feature_selection_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # Additional plot: All ensemble metrics together
    plt.figure(figsize=(12, 8))
    
    colors_metrics = ['blue', 'green', 'orange', 'red', 'purple']
    for i, metric in enumerate(metrics):
        plt.errorbar(feature_counts, ensemble_data[metric], yerr=ensemble_stds[metric],
                    fmt='o-', label=metric_titles[i], color=colors_metrics[i], 
                    linewidth=2, capsize=3)
    
    plt.xlabel('Number of PE Header Features')
    plt.ylabel('Score')
    plt.title('PE Header Ensemble Performance: All Metrics vs Number of Features')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.ylim(0, 1)
    plt.savefig('pe_header_ensemble_all_metrics.png', dpi=300, bbox_inches='tight')
    plt.show()

def main():
    """Main function to run the complete PE header feature selection pipeline."""
    
    # Configuration
    input_csv = "pe_headers_dataset.csv"
    optimal_output_csv = "(test_purpose)optimal_pe_headers_dataset.csv"
    
    # Feature counts to test (limited by the 52 PE header features available)
    feature_counts = [10, 15, 20, 25, 30, 35, 40, 45, 50]
    cv_folds = 5
    random_state = 42
    
    try:
        # Load data
        X, y, pe_header_cols = load_and_prepare_data(input_csv)
        
        # Filter feature counts to not exceed available features
        max_features = X.shape[1]
        feature_counts = [k for k in feature_counts if k <= max_features]
        logging.info(f"Testing feature counts: {feature_counts} (max available: {max_features})")
        
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
        logging.info("PE HEADER FEATURE SELECTION COMPLETED SUCCESSFULLY!")
        logging.info("="*60)
        logging.info(f"✅ Optimal PE header features: {optimal_k}")
        logging.info(f"✅ Best ensemble metrics:")
        logging.info(f"   - Accuracy: {best_result['ensemble_means']['accuracy']:.4f}")
        logging.info(f"   - Precision: {best_result['ensemble_means']['precision']:.4f}")
        logging.info(f"   - Recall: {best_result['ensemble_means']['recall']:.4f}")
        logging.info(f"   - F1-Score: {best_result['ensemble_means']['f1']:.4f}")
        logging.info(f"   - AUC: {best_result['ensemble_means']['auc']:.4f}")
        logging.info(f"✅ Optimal dataset saved: {optimal_output_csv}")
        logging.info(f"✅ Results plots saved: pe_header_feature_selection_results.png, pe_header_ensemble_all_metrics.png")
        
        # Show top selected features
        logging.info(f"\nTop 10 selected PE header features:")
        feature_scores = final_selector.scores_[final_selector.get_support()]
        feature_score_pairs = list(zip(selected_features, feature_scores))
        feature_score_pairs.sort(key=lambda x: x[1], reverse=True)
        
        for i, (feature, score) in enumerate(feature_score_pairs[:min(10, len(feature_score_pairs))]):
            logging.info(f"  {i+1:2d}. {feature}: {score:.4f}")
        
    except Exception as e:
        logging.error(f"Error in PE header feature selection pipeline: {str(e)}")
        raise

if __name__ == "__main__":
    main()