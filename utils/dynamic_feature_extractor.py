"""
Clean Dynamic Feature Extractor
ONLY responsible for converting Cuckoo reports to feature vectors
"""

import json
import os
import numpy as np
import pandas as pd
from typing import Dict, List, Union, Set
import logging

logger = logging.getLogger(__name__)

class DynamicFeatureExtractor:
    """
    Converts Cuckoo sandbox reports into ML-ready feature vectors
    """
    
    def __init__(self, feature_mapping_file: str = None):
        """
        Initialize feature extractor
        
        Args:
            feature_mapping_file: JSON file mapping feature IDs to names
        """
        self.feature_mapping = {}
        self.feature_id_to_position = {}
        self.feature_names = []
        
        if feature_mapping_file:
            self._load_feature_mapping(feature_mapping_file)
    
    def save_features_to_csv(self, features_df: pd.DataFrame, csv_path: str, 
                         sample_id: int = None, family_label: int = 0, type_label: int = 0,
                         create_new: bool = False) -> None:
        """
        Save extracted feature vectors to CSV in training dataset format
        
        Args:
            features_df: DataFrame with extracted features (from extract_features_from_cuckoo_json)
            csv_path: Path to save/append the CSV file
            sample_id: Unique sample identifier (auto-generated if None)
            family_label: Family label (0 for unknown/benign, >0 for known families)
            type_label: Binary classification label (0=benign, 1=malware)
            create_new: If True, create new CSV; if False, append to existing
        """
        try:
            # Generate sample_id if not provided
            if sample_id is None:
                if os.path.exists(csv_path) and not create_new:
                    # Read existing CSV to get next sample_id
                    existing_df = pd.read_csv(csv_path)
                    if 'sample_id' in existing_df.columns and len(existing_df) > 0:
                        sample_id = existing_df['sample_id'].max() + 1
                    else:
                        sample_id = 1
                else:
                    sample_id = 1
            
            # Prepare the row to add
            new_row = {
                'sample_id': sample_id,
                'sample_type': 1,  # 1 for dynamic analysis
                'family_label': family_label,
                'type_label': type_label
            }
            
            # Add all feature columns
            for col in features_df.columns:
                new_row[col] = features_df[col].iloc[0]
            
            # Create DataFrame for the new row
            new_row_df = pd.DataFrame([new_row])
            
            # Handle CSV creation/appending
            if create_new or not os.path.exists(csv_path):
                # Create new CSV
                new_row_df.to_csv(csv_path, index=False)
                logger.info(f"Created new CSV with 1 sample: {csv_path}")
            else:
                # Append to existing CSV
                # Read existing CSV to ensure column consistency
                existing_df = pd.read_csv(csv_path)
                
                # Check if columns match
                existing_cols = set(existing_df.columns)
                new_cols = set(new_row_df.columns)
                
                if existing_cols != new_cols:
                    logger.warning("Column mismatch detected - aligning columns")
                    
                    # Get all unique columns
                    all_cols = ['sample_id', 'sample_type', 'family_label', 'type_label']
                    feature_cols = sorted([col for col in (existing_cols | new_cols) 
                                        if col not in all_cols])
                    all_cols.extend(feature_cols)
                    
                    # Reindex both DataFrames to have same columns
                    existing_df = existing_df.reindex(columns=all_cols, fill_value=0)
                    new_row_df = new_row_df.reindex(columns=all_cols, fill_value=0)
                
                # Append new row
                combined_df = pd.concat([existing_df, new_row_df], ignore_index=True)
                combined_df.to_csv(csv_path, index=False)
                
                logger.info(f"Appended sample {sample_id} to CSV: {csv_path} (Total: {len(combined_df)})")
                
        except Exception as e:
            logger.error(f"Failed to save features to CSV: {e}")
            raise

    def extract_features_from_cuckoo_json(self, cuckoo_report: Union[str, dict]) -> pd.DataFrame:
        """
        Main extraction method - converts Cuckoo report to feature DataFrame
        
        Args:
            cuckoo_report: Cuckoo JSON report (string or dict)
            
        Returns:
            pandas DataFrame with feature columns matching training data
        """
        # Parse JSON if needed
        if isinstance(cuckoo_report, str):
            try:
                report_data = json.loads(cuckoo_report)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in Cuckoo report")
                return self._empty_dataframe()
        else:
            report_data = cuckoo_report
        
        if not self.feature_mapping:
            logger.warning("No feature mapping loaded")
            return self._empty_dataframe()
        
        # Initialize feature vector (all zeros)
        feature_ids = sorted(self.feature_mapping.keys())
        feature_vector = np.zeros(len(feature_ids))
        
        # Extract all features
        found_features = self._extract_all_features(report_data)
        
        # Set found features to 1
        features_set = 0
        for feature_id in found_features:
            if feature_id in self.feature_id_to_position:
                position = self.feature_id_to_position[feature_id]
                feature_vector[position] = 1
                features_set += 1
        
        logger.debug(f"Found {len(found_features)} total features, set {features_set} in vector")
        
        # Create DataFrame with correct column names
        feature_columns = [str(fid) for fid in feature_ids]
        features_df = pd.DataFrame([feature_vector], columns=feature_columns)
        
        return features_df
    
    def _extract_all_features(self, report_data: dict) -> Set[int]:
        """Extract all feature types from report"""
        found_features = set()
        
        # Extract from all sections
        found_features.update(self._extract_api_calls(report_data))
        found_features.update(self._extract_registry_operations(report_data))
        found_features.update(self._extract_file_operations(report_data))
        found_features.update(self._extract_directory_operations(report_data))
        found_features.update(self._extract_string_features(report_data))
        found_features.update(self._extract_network_features(report_data))
        found_features.update(self._extract_system_features(report_data))
        found_features.update(self._extract_dropped_file_features(report_data))
        found_features.update(self._extract_signature_features(report_data))
        
        return found_features
    
    def _extract_api_calls(self, report_data: dict) -> Set[int]:
        """Extract API call features"""
        found_features = set()
        
        try:
            behavior = report_data.get('behavior', {})
            processes = behavior.get('processes', [])
            
            for process in processes:
                calls = process.get('calls', [])
                for call in calls:
                    api_name = call.get('api', '')
                    if api_name:
                        # Look for "API:{api_name}" in feature mapping
                        for feature_id, feature_name in self.feature_mapping.items():
                            if feature_name == f"API:{api_name}":
                                found_features.add(feature_id)
                                break
        
        except Exception as e:
            logger.debug(f"Error extracting API calls: {e}")
        
        return found_features
    
    def _extract_registry_operations(self, report_data: dict) -> Set[int]:
        """Extract registry operation features"""
        found_features = set()
        
        try:
            behavior = report_data.get('behavior', {})
            summary = behavior.get('summary', {})
            
            # Registry keys
            reg_keys = summary.get('regkey_written', []) + summary.get('regkey_deleted', [])
            for reg_key in reg_keys:
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("REG:") and reg_key.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting registry operations: {e}")
        
        return found_features
    
    def _extract_file_operations(self, report_data: dict) -> Set[int]:
        """Extract file operation features"""
        found_features = set()
        
        try:
            behavior = report_data.get('behavior', {})
            summary = behavior.get('summary', {})
            
            # File operations
            files = (summary.get('file_written', []) + 
                    summary.get('file_deleted', []) + 
                    summary.get('file_copied', []))
            
            for file_path in files:
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("FILE:") and file_path.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting file operations: {e}")
        
        return found_features
    
    def _extract_directory_operations(self, report_data: dict) -> Set[int]:
        """Extract directory operation features"""
        found_features = set()
        
        try:
            behavior = report_data.get('behavior', {})
            summary = behavior.get('summary', {})
            
            # Directory operations
            dirs = summary.get('directory_created', []) + summary.get('directory_removed', [])
            for dir_path in dirs:
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("DIR:") and dir_path.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting directory operations: {e}")
        
        return found_features
    
    def _extract_string_features(self, report_data: dict) -> Set[int]:
        """Extract string-based features"""
        found_features = set()
        
        try:
            strings = report_data.get('strings', [])
            for string_item in strings:
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("STR:") and string_item.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting string features: {e}")
        
        return found_features
    
    def _extract_network_features(self, report_data: dict) -> Set[int]:
        """Extract network activity features"""
        found_features = set()
        
        try:
            network = report_data.get('network', {})
            
            # DNS requests
            dns_requests = network.get('dns', [])
            for dns in dns_requests:
                domain = dns.get('request', '')
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("NET:") and domain.upper() in feature_name.upper():
                        found_features.add(feature_id)
            
            # HTTP requests
            http_requests = network.get('http', [])
            for http in http_requests:
                host = http.get('host', '')
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("NET:") and host.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting network features: {e}")
        
        return found_features
    
    def _extract_system_features(self, report_data: dict) -> Set[int]:
        """Extract system-level features"""
        found_features = set()
        
        try:
            behavior = report_data.get('behavior', {})
            summary = behavior.get('summary', {})
            
            # System operations
            mutexes = summary.get('mutex', [])
            for mutex in mutexes:
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("SYS:") and mutex.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting system features: {e}")
        
        return found_features
    
    def _extract_dropped_file_features(self, report_data: dict) -> Set[int]:
        """Extract dropped file features"""
        found_features = set()
        
        try:
            dropped_files = report_data.get('dropped', [])
            
            for file_info in dropped_files:
                file_name = file_info.get('name', '')
                file_type = file_info.get('type', '')
                
                # File extensions
                if '.' in file_name:
                    ext = file_name.split('.')[-1].lower()
                    for feature_id, feature_name in self.feature_mapping.items():
                        if feature_name == f"DROP:EXTENSION:{ext}":
                            found_features.add(feature_id)
                
                # File types
                if file_type:
                    for feature_id, feature_name in self.feature_mapping.items():
                        if feature_name == f"DROP:TYPE:{file_type}":
                            found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting dropped file features: {e}")
        
        return found_features
    
    def _extract_signature_features(self, report_data: dict) -> Set[int]:
        """Extract signature-based features"""
        found_features = set()
        
        try:
            signatures = report_data.get('signatures', [])
            for sig in signatures:
                sig_name = sig.get('name', '')
                for feature_id, feature_name in self.feature_mapping.items():
                    if feature_name.startswith("SIG:") and sig_name.upper() in feature_name.upper():
                        found_features.add(feature_id)
        
        except Exception as e:
            logger.debug(f"Error extracting signature features: {e}")
        
        return found_features
    
    def _load_feature_mapping(self, mapping_file: str):
        """Load feature mapping from JSON file"""
        try:
            print(f"🔍 DEBUG: Loading mapping from: {mapping_file}")
            print(f"🔍 DEBUG: File exists: {os.path.exists(mapping_file)}")

            with open(mapping_file, 'r') as f:
                self.feature_mapping = json.load(f)
            
            print(f"🔍 DEBUG: Raw mapping loaded: {len(self.feature_mapping)} features")

            # Convert string keys to integers
            self.feature_mapping = {int(k): v for k, v in self.feature_mapping.items()}
            
            print(f"🔍 DEBUG: After conversion: {len(self.feature_mapping)} features")
            print(f"🔍 DEBUG: First 5 feature IDs: {list(self.feature_mapping.keys())[:5]}")

            # Create position mapping
            feature_ids = sorted(self.feature_mapping.keys())
            self.feature_id_to_position = {feature_id: i for i, feature_id in enumerate(feature_ids)}
            self.feature_names = [self.feature_mapping[fid] for fid in feature_ids]
            
            logger.info(f"Loaded {len(self.feature_mapping)} features from {mapping_file}")
            
        except Exception as e:
            logger.error(f"Failed to load feature mapping: {e}")
            raise
        
    
    def _empty_dataframe(self) -> pd.DataFrame:
        """Return empty DataFrame with correct structure"""
        if self.feature_mapping:
            feature_ids = sorted(self.feature_mapping.keys())
            feature_columns = [str(fid) for fid in feature_ids]
            return pd.DataFrame(columns=feature_columns)
        else:
            return pd.DataFrame()
    
    def get_feature_count(self) -> int:
        """Get total number of features"""
        return len(self.feature_mapping)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_names