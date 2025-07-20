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

def evaluate_virustotal_logic(vt_stats: Dict) -> Dict:
    """
    Evaluate VirusTotal results using direct majority rule logic
    
    Args:
        vt_stats (dict): VirusTotal stats from API response
        
    Returns:
        dict: Decision result with action and reasoning
    """
    # Extract detection counts
    malicious = vt_stats.get('malicious', 0)
    suspicious = vt_stats.get('suspicious', 0)
    harmless = vt_stats.get('harmless', 0)
    undetected = vt_stats.get('undetected', 0)
    
    # Calculate threat vs clean counts
    threat_count = malicious + suspicious
    clean_count = harmless + undetected
    total_meaningful = threat_count + clean_count
    
    # Log the decision process
    logger.info(f"VT Direct Logic: {threat_count} threat detections vs {clean_count} clean detections")
    
    # Apply direct majority rule
    if threat_count > clean_count:
        confidence = min(0.95, 0.5 + (threat_count / total_meaningful) if total_meaningful > 0 else 0.5)
        return {
            'decision': 'malicious',
            'confidence': confidence,
            'reason': f'{threat_count} engines detected threats vs {clean_count} clean (majority rule)',
            'action': 'final_verdict_ransomware',
            'stage': 'vt_malware_detected',
            'detection_counts': {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'threat_total': threat_count,
                'clean_total': clean_count
            }
        }
    else:
        confidence = min(0.95, (clean_count / total_meaningful) if total_meaningful > 0 else 0.5)
        return {
            'decision': 'benign',
            'confidence': confidence,
            'reason': f'{clean_count} engines found clean vs {threat_count} threats (majority rule)',
            'action': 'final_verdict_benign',
            'stage': 'vt_benign_confirmed',
            'detection_counts': {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'threat_total': threat_count,
                'clean_total': clean_count
            }
        }

def analyze_file_signature(file_path: str, security_mode: str = None) -> Dict:
    """
    Complete signature analysis workflow for a file
    
    Args:
        file_path (str): Path to the file to analyze
        security_mode (str): Ignored - kept for backward compatibility
        
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
            # Step 4: Evaluate using direct logic
            vt_data = vt_response['data']
            stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            result = evaluate_virustotal_logic(stats)
            
            # Add metadata
            result.update({
                'file_hash': file_hash,
                'vt_response': vt_data,
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
        result = analyze_file_signature(test_file_path)
        
        print(f"Result: {result['decision']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Reason: {result['reason']}")
        print(f"Action: {result['action']}")
        print(f"Hash: {result.get('file_hash', 'N/A')}")
        
        if result.get('detection_counts'):
            counts = result['detection_counts']
            print(f"Detection Summary:")
            print(f"  Malicious: {counts['malicious']}")
            print(f"  Suspicious: {counts['suspicious']}")
            print(f"  Harmless: {counts['harmless']}")
            print(f"  Undetected: {counts['undetected']}")
            print(f"  Threat Total: {counts['threat_total']}")
            print(f"  Clean Total: {counts['clean_total']}")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        test_signature_checking(sys.argv[1])
    else:
        print("Usage: python virustotal_check.py <file_path>")
        print("Example: python virustotal_check.py /path/to/test.exe")