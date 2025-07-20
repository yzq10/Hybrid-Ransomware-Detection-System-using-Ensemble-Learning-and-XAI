import pefile
import logging
import json
from pathlib import Path
from typing import Dict, Tuple, Optional

# Configure logging
logger = logging.getLogger(__name__)

def extract_pe_features(file_path: str, feature_mapping_file: str = None) -> Tuple[Dict, Optional[str]]:
    """
    Extract PE features matching the ensemble training data (exactly 225 features)
    
    Args:
        file_path (str): Path to the PE file
        feature_mapping_file (str): Path to feature_names.json from training
        
    Returns:
        tuple: (features_dict, error_message)
               features_dict contains exactly 225 features matching training data
               error_message is None if extraction succeeded
    """
    try:
        # Load expected feature names from training
        expected_features = []
        if feature_mapping_file and Path(feature_mapping_file).exists():
            try:
                with open(feature_mapping_file, 'r') as f:
                    feature_data = json.load(f)
                expected_features = feature_data.get('feature_names', [])
                logger.debug(f"Loaded {len(expected_features)} expected features from training")
            except Exception as e:
                logger.warning(f"Could not load feature mapping: {e}")
        
        # Parse PE file
        pe = pefile.PE(file_path)
        
        # Extract available features
        available_features = {}
        
        # Extract PE header features
        _extract_pe_header_features(pe, available_features)
        
        # Extract API and DLL features from imports
        _extract_import_features(pe, available_features)
        
        # Create final feature vector matching training data
        if expected_features:
            final_features = {}
            matched_count = 0
            
            for feature_name in expected_features:
                if feature_name in available_features:
                    final_features[feature_name] = available_features[feature_name]
                    matched_count += 1
                else:
                    # Default value for missing features
                    final_features[feature_name] = 0
            
            logger.debug(f"Matched {matched_count}/{len(expected_features)} features from PE file")
            return final_features, None
        else:
            logger.warning("No feature mapping found, returning available features")
            return available_features, None
        
    except Exception as e:
        logger.error(f"Error extracting features from {file_path}: {str(e)}")
        return None, str(e)

def _extract_pe_header_features(pe: pefile.PE, features: Dict):
    """Extract PE header features with PE_ prefix"""
    try:
        # DOS Header features (with PE_ prefix)
        features['PE_e_cblp'] = pe.DOS_HEADER.e_cblp
        features['PE_e_oemid'] = pe.DOS_HEADER.e_oemid
        features['PE_e_oeminfo'] = pe.DOS_HEADER.e_oeminfo
        features['PE_e_lfanew'] = pe.DOS_HEADER.e_lfanew
        
        # File Header features (with PE_ prefix)
        features['PE_Machine'] = pe.FILE_HEADER.Machine
        features['PE_NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['PE_TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['PE_NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
        features['PE_SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['PE_Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # Optional Header features (with PE_ prefix)
        if hasattr(pe, 'OPTIONAL_HEADER'):
            features['PE_Magic'] = pe.OPTIONAL_HEADER.Magic
            features['PE_SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['PE_SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['PE_ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['PE_SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['PE_FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['PE_MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['PE_MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['PE_MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            features['PE_MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
            features['PE_SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            features['PE_Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            features['PE_DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            features['PE_SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['PE_SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        
    except Exception as e:
        logger.warning(f"Error extracting PE header features: {e}")

def _extract_import_features(pe: pefile.PE, features: Dict):
    """Extract API and DLL features from PE imports"""
    try:
        # Initialize all possible API and DLL features to 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                # Mark DLL as present (API_DLL_xxx format)
                dll_feature_name = f"API_DLL_{dll_name}"
                features[dll_feature_name] = 1
                
                # Check each imported function
                for imp in entry.imports:
                    if imp.name:
                        try:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            # Create API feature name (API_API_dll.function format)
                            api_feature_name = f"API_API_{dll_name}.{func_name}"
                            features[api_feature_name] = 1
                        except:
                            continue
                    elif imp.ordinal:
                        # Handle ordinal imports
                        api_feature_name = f"API_API_{dll_name}.ordinal_{imp.ordinal}"
                        features[api_feature_name] = 1
        
    except Exception as e:
        logger.warning(f"Error extracting import features: {e}")

# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        feature_mapping = "models/static_ensemble/feature_names.json"
        
        print(f"Testing feature extraction on: {test_file}")
        print(f"Using feature mapping: {feature_mapping}")
        
        features, error = extract_pe_features(test_file, feature_mapping)
        
        if error:
            print(f"Error: {error}")
        else:
            print(f"Successfully extracted {len(features)} features")
            
            # Count PE vs API features
            pe_features = {k: v for k, v in features.items() if k.startswith('PE_')}
            api_features = {k: v for k, v in features.items() if k.startswith('API_')}
            api_present = sum(1 for v in api_features.values() if v == 1)
            
            print(f"PE features: {len(pe_features)}")
            print(f"API features: {len(api_features)} total, {api_present} present")
            
            # Show some examples of present features
            print("\nPresent API features (first 10):")
            present_apis = {k: v for k, v in api_features.items() if v == 1}
            for i, (k, v) in enumerate(present_apis.items()):
                if i < 10:
                    print(f"  {k}")
                    
            print(f"\nTotal present features: {sum(1 for v in features.values() if v != 0)}")
    else:
        print("Usage: python static_feature_extractor.py <pe_file_path>")
        print("Make sure feature_names.json is in models/static_ensemble/")