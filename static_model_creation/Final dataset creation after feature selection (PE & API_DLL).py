"""
Combine Optimal PE Headers + API/DLL Features into Final Static Dataset
Creates the final combined dataset for static ensemble training
Updated for XGBoost + SVM + Random Forest ensemble
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_and_validate_datasets(pe_csv_path, api_dll_csv_path):
    """Load and validate both optimal datasets."""
    logging.info("="*60)
    logging.info("LOADING AND VALIDATING OPTIMAL DATASETS")
    logging.info("="*60)
    
    # Load PE headers dataset
    logging.info(f"Loading PE headers dataset from: {pe_csv_path}")
    pe_df = pd.read_csv(pe_csv_path)
    logging.info(f"  PE dataset shape: {pe_df.shape}")
    
    # Load API/DLL dataset
    logging.info(f"Loading API/DLL dataset from: {api_dll_csv_path}")
    api_dll_df = pd.read_csv(api_dll_csv_path)
    logging.info(f"  API/DLL dataset shape: {api_dll_df.shape}")
    
    # Identify column types in both datasets
    pe_identifier_cols = ['SHA256', 'filename']
    pe_family_cols = [col for col in pe_df.columns if col.startswith('_family')]
    pe_target_col = 'Malware_Type'
    pe_feature_cols = [col for col in pe_df.columns 
                       if col not in pe_identifier_cols + pe_family_cols + [pe_target_col]]
    
    api_identifier_cols = ['SHA256', 'filename']
    api_family_cols = [col for col in api_dll_df.columns if col.startswith('_family')]
    api_target_col = 'Malware_Type'
    api_feature_cols = [col for col in api_dll_df.columns 
                        if col not in api_identifier_cols + api_family_cols + [api_target_col]]
    
    logging.info(f"PE Header Features:")
    logging.info(f"  - Identifier columns: {pe_identifier_cols}")
    logging.info(f"  - Family columns: {len(pe_family_cols)}")
    logging.info(f"  - Feature columns: {len(pe_feature_cols)}")
    logging.info(f"  - Target column: {pe_target_col}")
    
    logging.info(f"API/DLL Features:")
    logging.info(f"  - Identifier columns: {api_identifier_cols}")
    logging.info(f"  - Family columns: {len(api_family_cols)}")
    logging.info(f"  - Feature columns: {len(api_feature_cols)}")
    logging.info(f"  - Target column: {api_target_col}")
    
    # Validation checks
    logging.info("\nValidation Checks:")
    
    # Check if both datasets have the same samples
    pe_hashes = set(pe_df['SHA256'])
    api_hashes = set(api_dll_df['SHA256'])
    
    common_hashes = pe_hashes.intersection(api_hashes)
    pe_only = pe_hashes - api_hashes
    api_only = api_hashes - pe_hashes
    
    logging.info(f"  ✓ PE dataset samples: {len(pe_hashes)}")
    logging.info(f"  ✓ API/DLL dataset samples: {len(api_hashes)}")
    logging.info(f"  ✓ Common samples: {len(common_hashes)}")
    
    if pe_only:
        logging.warning(f"  ⚠️  PE-only samples: {len(pe_only)}")
    if api_only:
        logging.warning(f"  ⚠️  API/DLL-only samples: {len(api_only)}")
    
    # Check target consistency for common samples
    pe_subset = pe_df[pe_df['SHA256'].isin(common_hashes)].set_index('SHA256')
    api_subset = api_dll_df[api_dll_df['SHA256'].isin(common_hashes)].set_index('SHA256')
    
    target_mismatch = (pe_subset[pe_target_col] != api_subset[api_target_col]).sum()
    if target_mismatch > 0:
        logging.error(f"  ❌ Target mismatch in {target_mismatch} samples!")
        raise ValueError("Target labels don't match between datasets")
    else:
        logging.info(f"  ✅ Target labels consistent across all common samples")
    
    # Check class distribution
    pe_class_dist = pe_df[pe_target_col].value_counts()
    api_class_dist = api_dll_df[api_target_col].value_counts()
    
    logging.info(f"PE Header Class Distribution:")
    logging.info(f"  - Benign (0): {pe_class_dist.get(0, 0)}")
    logging.info(f"  - Ransomware (1): {pe_class_dist.get(1, 0)}")
    
    logging.info(f"API/DLL Class Distribution:")
    logging.info(f"  - Benign (0): {api_class_dist.get(0, 0)}")
    logging.info(f"  - Ransomware (1): {api_class_dist.get(1, 0)}")
    
    return pe_df, api_dll_df, common_hashes, pe_feature_cols, api_feature_cols

def combine_datasets(pe_df, api_dll_df, common_hashes, pe_feature_cols, api_feature_cols, 
                    strategy='inner_join'):
    """Combine the two optimal datasets using specified strategy."""
    logging.info("\n" + "="*60)
    logging.info("COMBINING OPTIMAL DATASETS")
    logging.info("="*60)
    
    logging.info(f"Combination strategy: {strategy}")
    
    if strategy == 'inner_join':
        # Only keep samples present in both datasets
        logging.info("Using INNER JOIN - keeping only common samples")
        
        # Filter both datasets to common samples
        pe_filtered = pe_df[pe_df['SHA256'].isin(common_hashes)].copy()
        api_filtered = api_dll_df[api_dll_df['SHA256'].isin(common_hashes)].copy()
        
        # Sort by SHA256 to ensure consistent ordering
        pe_filtered = pe_filtered.sort_values('SHA256').reset_index(drop=True)
        api_filtered = api_filtered.sort_values('SHA256').reset_index(drop=True)
        
        # Verify ordering is consistent
        if not (pe_filtered['SHA256'] == api_filtered['SHA256']).all():
            raise ValueError("SHA256 ordering mismatch after sorting")
        
        # Create combined dataset
        combined_df = pe_filtered[['SHA256', 'filename', 'Malware_Type']].copy()
        
        # Add family columns if they exist
        pe_family_cols = [col for col in pe_filtered.columns if col.startswith('_family')]
        if pe_family_cols:
            combined_df = pd.concat([combined_df, pe_filtered[pe_family_cols]], axis=1)
        
        # Add PE header features with prefix
        for col in pe_feature_cols:
            combined_df[f'PE_{col}'] = pe_filtered[col].values
        
        # Add API/DLL features with prefix
        for col in api_feature_cols:
            combined_df[f'API_{col}'] = api_filtered[col].values
        
        logging.info(f"✅ Combined dataset created using inner join")
        logging.info(f"  - Final samples: {len(combined_df)}")
        
    elif strategy == 'outer_join':
        # Keep all samples, fill missing with appropriate values
        logging.info("Using OUTER JOIN - keeping all samples with imputation")
        
        # Merge on SHA256
        combined_df = pd.merge(pe_df, api_dll_df, on=['SHA256', 'filename', 'Malware_Type'], 
                              how='outer', suffixes=('_PE', '_API'))
        
        # Handle missing values
        # PE features: fill with median for numerical
        for col in pe_feature_cols:
            pe_col = f'{col}_PE' if f'{col}_PE' in combined_df.columns else col
            if pe_col in combined_df.columns:
                combined_df[pe_col] = combined_df[pe_col].fillna(combined_df[pe_col].median())
        
        # API/DLL features: fill with 0 for binary
        for col in api_feature_cols:
            api_col = f'{col}_API' if f'{col}_API' in combined_df.columns else col
            if api_col in combined_df.columns:
                combined_df[api_col] = combined_df[api_col].fillna(0)
        
        logging.info(f"✅ Combined dataset created using outer join")
        logging.info(f"  - Final samples: {len(combined_df)}")
        
    else:
        raise ValueError(f"Unknown combination strategy: {strategy}")
    
    return combined_df

def analyze_combined_dataset(combined_df):
    """Analyze the combined dataset characteristics."""
    logging.info("\n" + "="*60)
    logging.info("ANALYZING COMBINED DATASET")
    logging.info("="*60)
    
    # Basic statistics
    logging.info(f"Combined Dataset Shape: {combined_df.shape}")
    
    # Identify feature types
    identifier_cols = ['SHA256', 'filename']
    family_cols = [col for col in combined_df.columns if col.startswith('_family')]
    target_col = 'Malware_Type'
    
    pe_feature_cols = [col for col in combined_df.columns if col.startswith('PE_')]
    api_feature_cols = [col for col in combined_df.columns if col.startswith('API_')]
    
    total_features = len(pe_feature_cols) + len(api_feature_cols)
    
    logging.info(f"Feature Breakdown:")
    logging.info(f"  - PE Header Features: {len(pe_feature_cols)}")
    logging.info(f"  - API/DLL Features: {len(api_feature_cols)}")
    logging.info(f"  - Total Features: {total_features}")
    logging.info(f"  - Identifier Columns: {len(identifier_cols)}")
    logging.info(f"  - Family Columns: {len(family_cols)}")
    logging.info(f"  - Target Column: 1")
    
    # Class distribution
    class_dist = combined_df[target_col].value_counts()
    logging.info(f"Final Class Distribution:")
    logging.info(f"  - Benign (0): {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(combined_df)*100:.1f}%)")
    logging.info(f"  - Ransomware (1): {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(combined_df)*100:.1f}%)")
    
    # Missing values check
    missing_values = combined_df.isnull().sum().sum()
    if missing_values > 0:
        logging.warning(f"  ⚠️  Missing values found: {missing_values}")
        missing_cols = combined_df.columns[combined_df.isnull().any()].tolist()
        logging.warning(f"  Columns with missing values: {missing_cols}")
    else:
        logging.info(f"  ✅ No missing values found")
    
    # Feature statistics
    feature_cols = pe_feature_cols + api_feature_cols
    if feature_cols:
        feature_stats = combined_df[feature_cols].describe()
        logging.info(f"Feature Statistics:")
        logging.info(f"  - Mean range: {feature_stats.loc['mean'].min():.4f} to {feature_stats.loc['mean'].max():.4f}")
        logging.info(f"  - Std range: {feature_stats.loc['std'].min():.4f} to {feature_stats.loc['std'].max():.4f}")
    
    # Data types
    pe_types = combined_df[pe_feature_cols].dtypes.value_counts() if pe_feature_cols else pd.Series()
    api_types = combined_df[api_feature_cols].dtypes.value_counts() if api_feature_cols else pd.Series()
    
    logging.info(f"Data Types:")
    logging.info(f"  PE Features: {dict(pe_types)}")
    logging.info(f"  API Features: {dict(api_types)}")
    
    return {
        'total_samples': len(combined_df),
        'total_features': total_features,
        'pe_features': len(pe_feature_cols),
        'api_features': len(api_feature_cols),
        'class_distribution': dict(class_dist),
        'missing_values': missing_values
    }

def save_combined_dataset(combined_df, output_path):
    """Save the combined dataset with metadata."""
    logging.info("\n" + "="*60)
    logging.info("SAVING COMBINED DATASET")
    logging.info("="*60)
    
    # Save main dataset
    combined_df.to_csv(output_path, index=False)
    logging.info(f"✅ Combined dataset saved to: {output_path}")
    
    # Create metadata file
    metadata_path = output_path.replace('.csv', '_metadata.txt')
    
    # Identify feature columns
    pe_feature_cols = [col for col in combined_df.columns if col.startswith('PE_')]
    api_feature_cols = [col for col in combined_df.columns if col.startswith('API_')]
    
    with open(metadata_path, 'w') as f:
        f.write("COMBINED STATIC FEATURE DATASET METADATA\n")
        f.write("="*50 + "\n\n")
        f.write(f"Dataset Shape: {combined_df.shape}\n")
        f.write(f"Total Features: {len(pe_feature_cols) + len(api_feature_cols)}\n")
        f.write(f"PE Header Features: {len(pe_feature_cols)}\n")
        f.write(f"API/DLL Features: {len(api_feature_cols)}\n\n")
        
        f.write("COLUMN STRUCTURE:\n")
        f.write("-" * 20 + "\n")
        f.write("- SHA256: File hash identifier\n")
        f.write("- filename: Original filename\n")
        f.write("- Malware_Type: Target (0=Benign, 1=Ransomware)\n")
        
        family_cols = [col for col in combined_df.columns if col.startswith('_family')]
        if family_cols:
            f.write("- _family_*: Malware family labels (if available)\n")
        
        f.write("- PE_*: PE Header features (numerical)\n")
        f.write("- API_*: API/DLL features (binary)\n\n")
        
        f.write("PE HEADER FEATURES:\n")
        f.write("-" * 20 + "\n")
        for i, col in enumerate(pe_feature_cols, 1):
            f.write(f"{i:2d}. {col}\n")
        
        f.write(f"\nAPI/DLL FEATURES:\n")
        f.write("-" * 20 + "\n")
        for i, col in enumerate(api_feature_cols, 1):
            f.write(f"{i:3d}. {col}\n")
        
        class_dist = combined_df['Malware_Type'].value_counts()
        f.write(f"\nCLASS DISTRIBUTION:\n")
        f.write("-" * 20 + "\n")
        f.write(f"Benign (0): {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(combined_df)*100:.1f}%)\n")
        f.write(f"Ransomware (1): {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(combined_df)*100:.1f}%)\n")
    
    logging.info(f"✅ Metadata saved to: {metadata_path}")
    
    return metadata_path

def main():
    """Main function to combine optimal PE and API/DLL datasets."""
    
    # Configuration
    pe_csv_path = "(test_purpose)optimal_pe_headers_dataset.csv"
    api_dll_csv_path = "(test_purpose)optimal_api_dll_dataset.csv"  # Assuming this exists from API/DLL selection
    output_csv_path = "final_static_features_dataset(600api_dll).csv"
    combination_strategy = "inner_join"  # or "outer_join"
    
    try:
        # Check if input files exist
        if not Path(pe_csv_path).exists():
            raise FileNotFoundError(f"PE headers dataset not found: {pe_csv_path}")
        
        if not Path(api_dll_csv_path).exists():
            raise FileNotFoundError(f"API/DLL dataset not found: {api_dll_csv_path}")
        
        # Load and validate datasets
        pe_df, api_dll_df, common_hashes, pe_feature_cols, api_feature_cols = load_and_validate_datasets(
            pe_csv_path, api_dll_csv_path
        )
        
        # Combine datasets
        combined_df = combine_datasets(
            pe_df, api_dll_df, common_hashes, pe_feature_cols, api_feature_cols, 
            strategy=combination_strategy
        )
        
        # Analyze combined dataset
        analysis_results = analyze_combined_dataset(combined_df)
        
        # Save combined dataset
        metadata_path = save_combined_dataset(combined_df, output_csv_path)
        
        # Final summary
        logging.info("\n" + "="*60)
        logging.info("DATASET COMBINATION COMPLETED SUCCESSFULLY!")
        logging.info("="*60)
        logging.info(f"✅ Final static features dataset: {output_csv_path}")
        logging.info(f"✅ Dataset metadata: {metadata_path}")
        logging.info(f"✅ Total samples: {analysis_results['total_samples']:,}")
        logging.info(f"✅ Total features: {analysis_results['total_features']}")
        logging.info(f"   - PE Header features: {analysis_results['pe_features']}")
        logging.info(f"   - API/DLL features: {analysis_results['api_features']}")
        logging.info(f"✅ Class balance: {analysis_results['class_distribution'][0]:,} benign, {analysis_results['class_distribution'][1]:,} ransomware")
        
        logging.info(f"\n🎯 READY FOR FINAL ENSEMBLE TRAINING!")
        logging.info(f"Next steps:")
        logging.info(f"1. Load {output_csv_path}")
        logging.info(f"2. Train final XGBoost + SVM + Random Forest ensemble")
        logging.info(f"3. Evaluate performance on combined feature set")
        logging.info(f"4. Deploy static analysis component")
        
        return combined_df, analysis_results
        
    except Exception as e:
        logging.error(f"Error in dataset combination: {str(e)}")
        raise

if __name__ == "__main__":
    main()