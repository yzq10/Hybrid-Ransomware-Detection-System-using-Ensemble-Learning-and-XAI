"""
VirusTotal Signature Checking Module
Handles hash calculation, VT API submission, and decision logic
"""

import hashlib
import requests
import time
import logging
import json
from typing import Dict, Tuple, Optional

# Configure logging
logger = logging.getLogger(__name__)

# VT API Configuration
VT_CONFIG = {
    'API_KEY': '65a8d775106589b4afe788599a71f3a0a43384c9029606d1f7694596cf730334',  # To be configured
    'BASE_URL': 'https://www.virustotal.com/api/v3',
    'RATE_LIMIT_DELAY': 15,  # seconds between requests (free tier)
    'MAX_RETRIES': 3,
    'TIMEOUT': 30
}

# Security Mode Configurations
SECURITY_MODES = {
    "CONSERVATIVE": {
        "malware_threshold": 0.05,     # 5% = malware
        "clean_threshold": 0.80,       # 80% clean required
        "max_malware_for_clean": 0.01, # 1% max for benign
        "coverage_threshold": 0.60
    },
    "BALANCED": {
        "malware_threshold": 0.10,     # 10% = malware  
        "clean_threshold": 0.70,       # 70% clean required
        "max_malware_for_clean": 0.02, # 2% max for benign
        "coverage_threshold": 0.50
    },
    "PERMISSIVE": {
        "malware_threshold": 0.15,     # 15% = malware
        "clean_threshold": 0.60,       # 60% clean required
        "max_malware_for_clean": 0.03, # 3% max for benign
        "coverage_threshold": 0.40
    }
}

# Default security mode
DEFAULT_SECURITY_MODE = "BALANCED"

class VTError(Exception):
    """Custom exception for VirusTotal API errors"""
    pass

class APIError(Exception):
    """Custom exception for API communication errors"""
    pass

def calculate_file_hash(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        str: SHA256 hash in hexadecimal format
        
    Raises:
        FileNotFoundError: If file doesn't exist
        Exception: For other file reading errors
    """
    try:
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        file_hash = sha256_hash.hexdigest()
        logger.info(f"Calculated hash for {file_path}: {file_hash}")
        return file_hash
        
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {str(e)}")
        raise

def submit_hash_to_virustotal(file_hash: str) -> Dict:
    """
    Submit file hash to VirusTotal API with retry logic
    
    Args:
        file_hash (str): SHA256 hash of the file
        
    Returns:
        dict: VirusTotal API response
        
    Raises:
        VTError: For VirusTotal-specific errors
        APIError: For API communication errors
    """
    url = f"{VT_CONFIG['BASE_URL']}/files/{file_hash}"
    headers = {
        'X-Apikey': VT_CONFIG['API_KEY'],
        'Accept': 'application/json'
    }
    
    for attempt in range(VT_CONFIG['MAX_RETRIES']):
        try:
            logger.debug(f"Submitting hash to VT (attempt {attempt + 1}): {file_hash}")
            
            response = requests.get(
                url,
                headers=headers,
                timeout=VT_CONFIG['TIMEOUT']
            )
            
            # Handle different response codes
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully retrieved VT report for hash: {file_hash}")
                return {
                    'status': 'completed',
                    'data': data
                }
            
            elif response.status_code == 404:
                logger.info(f"Hash not found in VT database: {file_hash}")
                return {
                    'status': 'not_found',
                    'data': None
                }
            
            elif response.status_code == 429:  # Rate limit
                if attempt < VT_CONFIG['MAX_RETRIES'] - 1:
                    wait_time = VT_CONFIG['RATE_LIMIT_DELAY'] * (attempt + 1)
                    logger.warning(f"Rate limit hit, waiting {wait_time}s before retry")
                    time.sleep(wait_time)
                    continue
                else:
                    raise VTError("Rate limit exceeded after maximum retries")
            
            elif response.status_code == 401:
                raise VTError("Invalid API key")
            
            elif response.status_code == 403:
                raise VTError("Access forbidden - check API key permissions")
            
            else:
                # For other errors, try to get error message from response
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', f'HTTP {response.status_code}')
                except:
                    error_msg = f'HTTP {response.status_code}'
                
                if attempt < VT_CONFIG['MAX_RETRIES'] - 1:
                    logger.warning(f"VT API error: {error_msg}, retrying...")
                    time.sleep(VT_CONFIG['RATE_LIMIT_DELAY'])
                    continue
                else:
                    raise VTError(f"VT API error: {error_msg}")
        
        except requests.exceptions.Timeout:
            if attempt < VT_CONFIG['MAX_RETRIES'] - 1:
                logger.warning("Request timeout, retrying...")
                time.sleep(VT_CONFIG['RATE_LIMIT_DELAY'])
                continue
            else:
                raise APIError("Request timeout after maximum retries")
        
        except requests.exceptions.ConnectionError:
            if attempt < VT_CONFIG['MAX_RETRIES'] - 1:
                logger.warning("Connection error, retrying...")
                time.sleep(VT_CONFIG['RATE_LIMIT_DELAY'])
                continue
            else:
                raise APIError("Connection error after maximum retries")
        
        except Exception as e:
            logger.error(f"Unexpected error in VT API call: {str(e)}")
            raise APIError(f"Unexpected error: {str(e)}")
    
    # Should not reach here, but just in case
    raise APIError("Maximum retries exceeded")

def retrieve_virustotal_report(file_hash: str) -> Dict:
    """
    Retrieve VirusTotal report for a file hash
    This is a wrapper around submit_hash_to_virustotal for clarity
    
    Args:
        file_hash (str): SHA256 hash of the file
        
    Returns:
        dict: VirusTotal report data
    """
    return submit_hash_to_virustotal(file_hash)

def calculate_vt_ratios(vt_stats: Dict) -> Dict:
    malicious = vt_stats.get('malicious', 0)
    suspicious = vt_stats.get('suspicious', 0)
    harmless = vt_stats.get('harmless', 0)
    undetected = vt_stats.get('undetected', 0)
    timeout = vt_stats.get('timeout', 0)
    confirmed_timeout = vt_stats.get('confirmed-timeout', 0)
    failure = vt_stats.get('failure', 0)
    type_unsupported = vt_stats.get('type-unsupported', 0)
    
    # Calculate total from all the individual counts
    total = malicious + suspicious + harmless + undetected + timeout + confirmed_timeout + failure + type_unsupported
    
    # FIXED: Engines that provided meaningful analysis (including "undetected")
    analyzed_engines = malicious + suspicious + harmless + undetected  # Include undetected!
    coverage_ratio = analyzed_engines / total if total > 0 else 0.0
    
    # UPDATED: Include undetected engines in clean ratio calculation
    # Rationale: If an engine scans and finds nothing, that's evidence of cleanliness
    malware_ratio = (malicious + suspicious) / total if total > 0 else 0.0
    clean_ratio = (harmless + undetected) / total if total > 0 else 0.0
    detection_count = malicious + suspicious
    
    return {
        'coverage_ratio': coverage_ratio,
        'malware_ratio': malware_ratio,
        'clean_ratio': clean_ratio,
        'detection_count': detection_count,
        'analyzed_engines': analyzed_engines,
        'total_engines': total
    }

def evaluate_virustotal_logic(vt_stats: Dict, security_mode: str = DEFAULT_SECURITY_MODE) -> Dict:
    """
    Evaluate VirusTotal results using the defined logic
    
    Args:
        vt_stats (dict): VirusTotal stats from API response
        security_mode (str): Security mode configuration
        
    Returns:
        dict: Decision result with action and reasoning
    """
    if security_mode not in SECURITY_MODES:
        logger.warning(f"Unknown security mode: {security_mode}, using default: {DEFAULT_SECURITY_MODE}")
        security_mode = DEFAULT_SECURITY_MODE
    
    ratios = calculate_vt_ratios(vt_stats)
    thresholds = SECURITY_MODES[security_mode]
    
    # 1. Coverage Check (Data Quality Gate)
    if ratios['coverage_ratio'] < thresholds['coverage_threshold']:
        return {
            'decision': 'insufficient_data',
            'confidence': 0.0,
            'reason': f'Only {ratios["coverage_ratio"]:.1%} engine coverage (min: {thresholds["coverage_threshold"]:.1%})',
            'action': 'proceed_to_static',
            'stage': 'vt_insufficient_coverage',
            'ratios': ratios
        }
    
    # 2. Malware Check
    if ratios['malware_ratio'] >= thresholds['malware_threshold']:
        confidence = min(0.95, 0.5 + ratios['malware_ratio'])
        return {
            'decision': 'malicious',
            'confidence': confidence,
            'reason': f'{ratios["malware_ratio"]:.1%} engines detected malware (threshold: {thresholds["malware_threshold"]:.1%})',
            'action': 'final_verdict_ransomware',
            'stage': 'vt_malware_detected',
            'ratios': ratios
        }
    
    # 3. Benign Check (High confidence clean)
    benign_conditions = (
        ratios['clean_ratio'] >= thresholds['clean_threshold'] and 
        ratios['malware_ratio'] <= thresholds['max_malware_for_clean']
    )
    
    if benign_conditions:
        confidence = min(0.95, ratios['clean_ratio'])
        return {
            'decision': 'benign',
            'confidence': confidence,
            'reason': f'{ratios["clean_ratio"]:.1%} clean, {ratios["malware_ratio"]:.1%} malware (clean threshold: {thresholds["clean_threshold"]:.1%})',
            'action': 'final_verdict_benign',
            'stage': 'vt_benign_confirmed',
            'ratios': ratios
        }
    
    # 4. Default: Ambiguous - Continue to static analysis
    return {
        'decision': 'ambiguous',
        'confidence': 0.5,
        'reason': f'{ratios["malware_ratio"]:.1%} malware detection (below threshold, needs analysis)',
        'action': 'proceed_to_static',
        'stage': 'vt_ambiguous',
        'ratios': ratios
    }

def analyze_file_signature(file_path: str, security_mode: str = DEFAULT_SECURITY_MODE) -> Dict:
    """
    Complete signature analysis workflow for a file
    
    Args:
        file_path (str): Path to the file to analyze
        security_mode (str): Security mode configuration
        
    Returns:
        dict: Complete analysis result
    """
    try:
        # Step 1: Calculate file hash
        logger.info(f"Starting signature analysis for: {file_path}")
        file_hash = calculate_file_hash(file_path)
        
        # Step 2: Submit to VirusTotal
        vt_response = retrieve_virustotal_report(file_hash)
        
        # Step 3: Handle different response scenarios
        if vt_response['status'] == 'not_found':
            return {
                'decision': 'unknown',
                'confidence': 0.0,
                'reason': 'File hash not found in VirusTotal database',
                'action': 'proceed_to_static',
                'stage': 'vt_not_found',
                'file_hash': file_hash,
                'vt_response': None
            }
        
        elif vt_response['status'] == 'completed':
            # Step 4: Evaluate the logic
            vt_data = vt_response['data']
            stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            result = evaluate_virustotal_logic(stats, security_mode)
            
            # Add metadata
            result.update({
                'file_hash': file_hash,
                'vt_response': vt_data,
                'security_mode': security_mode,
                'scan_date': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_date')
            })
            
            logger.info(f"Signature analysis complete: {result['decision']} - {result['reason']}")
            return result
        
        else:
            # Error case
            return {
                'decision': 'error',
                'confidence': 0.0,
                'reason': f'VirusTotal API error: {vt_response.get("error", "Unknown error")}',
                'action': 'proceed_to_static',
                'stage': 'vt_api_error',
                'file_hash': file_hash,
                'vt_response': vt_response
            }
        
    except (VTError, APIError) as e:
        logger.error(f"Signature analysis failed for {file_path}: {str(e)}")
        return {
            'decision': 'error',
            'confidence': 0.0,
            'reason': f'Signature analysis failed: {str(e)}',
            'action': 'proceed_to_static',
            'stage': 'signature_error',
            'file_hash': None,
            'error': str(e)
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in signature analysis for {file_path}: {str(e)}")
        return {
            'decision': 'error',
            'confidence': 0.0,
            'reason': f'Unexpected error: {str(e)}',
            'action': 'proceed_to_static',
            'stage': 'unexpected_error',
            'file_hash': None,
            'error': str(e)
        }
    
# Convenience function for quick testing
def test_signature_checking(test_file_path: str):
    """
    Test function for signature checking module
    
    Args:
        test_file_path (str): Path to test file
    """
    print(f"Testing signature checking with: {test_file_path}")
    
    try:
        result = analyze_file_signature(test_file_path, "BALANCED")
        
        print(f"Result: {result['decision']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Reason: {result['reason']}")
        print(f"Action: {result['action']}")
        print(f"Hash: {result.get('file_hash', 'N/A')}")
        
        if result.get('ratios'):
            ratios = result['ratios']
            print(f"Coverage: {ratios['coverage_ratio']:.1%}")
            print(f"Malware: {ratios['malware_ratio']:.1%}")
            print(f"Clean: {ratios['clean_ratio']:.1%}")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        test_signature_checking(sys.argv[1])
    else:
        print("Usage: python signature_checking.py <file_path>")
        print("Example: python signature_checking.py /path/to/test.exe")