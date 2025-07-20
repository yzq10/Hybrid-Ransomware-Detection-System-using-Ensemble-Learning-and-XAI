import os
import time
import json
import requests
import logging
from typing import Optional, Dict, Any

# Configuration
CUCKOO_CONFIG = {
    'BASE_URL': 'http://192.168.11.153:8090',  # Changed from API_URL to BASE_URL
    'API_KEY': 'CEPoNYH2ntxMySOETwQysA',
    'WEB_URL': 'http://192.168.11.153:8080',
    'ANALYSIS_TIMEOUT': 360,  # 5 minutes max wait
    'CHECK_INTERVAL': 10,     # Check status every 10 seconds
    'MAX_RETRIES': 50,        # Maximum status check retries
    'FILE_SIZE_LIMIT': 500 * 1024 * 1024,  # 500MB limit
}

# Setup logging
logger = logging.getLogger(__name__)

class CuckooAnalysisError(Exception):
    """Custom exception for Cuckoo analysis errors"""
    pass

class CuckooClient:
    """Cuckoo Sandbox API client for hybrid detection system"""
    
    def __init__(self, base_url: str = None, api_key: str = None, timeout: int = None):
        self.base_url = base_url or CUCKOO_CONFIG['BASE_URL']
        self.api_key = api_key or CUCKOO_CONFIG['API_KEY']
        self.timeout = timeout or CUCKOO_CONFIG['ANALYSIS_TIMEOUT']
        self.session = requests.Session()
        self.session.timeout = 60  # HTTP request timeout
        
        # Set up authentication header
        if self.api_key:
            self.session.headers.update({'Authorization': f'Bearer {self.api_key}'})
    
    def submit_file_and_wait(self, file_path: str) -> Dict[str, Any]:
        """
        Submit file to Cuckoo, wait for completion, and return JSON report.
        This is the main method for the hybrid detection system.
        
        Args:
            file_path (str): Path to the executable file
            
        Returns:
            dict: Cuckoo analysis report (JSON format)
            
        Raises:
            CuckooAnalysisError: If analysis fails or times out
        """
        try:
            # Validate file
            self._validate_file(file_path)
            
            # Submit file
            logger.info(f"Submitting file to Cuckoo: {os.path.basename(file_path)}")
            task_id = self._submit_file(file_path)
            
            if not task_id:
                raise CuckooAnalysisError("Failed to submit file to Cuckoo sandbox")
            
            logger.info(f"File submitted successfully, Task ID: {task_id}")
            
            # Wait for completion
            logger.info(f"Waiting for analysis completion (max {self.timeout}s)...")
            if not self._wait_for_completion(task_id):
                raise CuckooAnalysisError(f"Analysis timed out after {self.timeout} seconds")
            
            # Get report
            logger.info(f"Retrieving analysis report for task {task_id}")
            report = self._get_report(task_id)
            
            if not report:
                raise CuckooAnalysisError("Failed to retrieve analysis report")
            
            logger.info(f"Analysis completed successfully for task {task_id}")
            return report
            
        except CuckooAnalysisError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in Cuckoo analysis: {str(e)}")
            raise CuckooAnalysisError(f"Unexpected error: {str(e)}")
    
    def _validate_file(self, file_path: str):
        """Validate file before submission"""
        if not os.path.exists(file_path):
            raise CuckooAnalysisError(f"File does not exist: {file_path}")
        
        if not os.path.isfile(file_path):
            raise CuckooAnalysisError(f"Path is not a file: {file_path}")
        
        file_size = os.path.getsize(file_path)
        if file_size > CUCKOO_CONFIG['FILE_SIZE_LIMIT']:
            raise CuckooAnalysisError(f"File too large: {file_size} bytes (limit: {CUCKOO_CONFIG['FILE_SIZE_LIMIT']})")
        
        if file_size == 0:
            raise CuckooAnalysisError("File is empty")
    
    # def _submit_file(self, file_path: str) -> Optional[int]:
    #     """Submit file to Cuckoo and return task ID"""
    #     try:
    #         with open(file_path, 'rb') as f:
    #             files = {'file': (os.path.basename(file_path), f)}
    #             data = {
    #                 'timeout': self.timeout,
    #             }
                
    #             # Fixed URL: removed /api prefix
    #             response = self.session.post(
    #                 f'{self.base_url}/tasks/create/file',
    #                 files=files,
    #                 data=data
    #             )
                
    #             if response.status_code == 200:
    #                 result = response.json()
    #                 logger.debug(f"Submit response: {result}")
                    
    #                 # Extract task ID from Cuckoo response
    #                 task_id = self._extract_task_id(result)
    #                 return task_id
    #             else:
    #                 logger.error(f"Failed to submit file: HTTP {response.status_code}")
    #                 logger.error(f"Response: {response.text}")
    #                 return None
                    
    #     except Exception as e:
    #         logger.error(f"Error submitting file: {str(e)}")
    #         return None
    

    def _submit_file(self, file_path: str) -> Optional[int]:
        """Submit file to Cuckoo and return task ID"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                # Removed timeout from data - let Cuckoo use its default analysis timeout
                data = {}
                
                # Fixed URL: removed /api prefix
                response = self.session.post(
                    f'{self.base_url}/tasks/create/file',
                    files=files,
                    data=data
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.debug(f"Submit response: {result}")
                    
                    # Extract task ID from Cuckoo response
                    task_id = self._extract_task_id(result)
                    return task_id
                else:
                    logger.error(f"Failed to submit file: HTTP {response.status_code}")
                    logger.error(f"Response: {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error submitting file: {str(e)}")
            return None

    def _extract_task_id(self, response: Dict[str, Any]) -> Optional[int]:
        """Extract task ID from Cuckoo API response"""
        try:
            # Standard Cuckoo format: {"task_id": 123}
            if 'task_id' in response:
                return int(response['task_id'])
            
            # Alternative format: {"task_ids": [123]}
            if 'task_ids' in response:
                task_ids = response['task_ids']
                if isinstance(task_ids, list) and len(task_ids) > 0:
                    return int(task_ids[0])
            
            # Check if response itself is the task ID
            if isinstance(response, int):
                return response
            
            logger.error(f"Could not extract task ID from response: {response}")
            return None
            
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Error extracting task ID: {str(e)}")
            return None
    
    def _wait_for_completion(self, task_id: int) -> bool:
        """Wait for analysis to complete"""
        start_time = time.time()
        retries = 0
        
        while retries < CUCKOO_CONFIG['MAX_RETRIES']:
            # Check timeout
            if time.time() - start_time > self.timeout:
                logger.error(f"Analysis timeout after {self.timeout} seconds")
                return False
            
            # Get status
            status = self._get_task_status(task_id)
            logger.debug(f"Task {task_id} status: {status} (retry {retries + 1})")
            
            if status == 'reported':
                logger.info(f"Analysis completed for task {task_id}")
                return True
            elif status in ['completed']:
                # Sometimes 'completed' means report is ready
                logger.info(f"Task {task_id} completed, checking for report...")
                time.sleep(2)  # Brief wait before checking report
                return True
            elif status in ['pending', 'running']:
                # Still processing
                logger.debug(f"Task {task_id} still processing ({status})")
                time.sleep(CUCKOO_CONFIG['CHECK_INTERVAL'])
                retries += 1
            elif status in ['failed', 'failure']:
                logger.error(f"Analysis failed for task {task_id}: {status}")
                return False
            elif status is None:
                # Could not get status
                logger.warning(f"Could not get status for task {task_id}, retrying...")
                time.sleep(CUCKOO_CONFIG['CHECK_INTERVAL'])
                retries += 1
            else:
                # Unknown status
                logger.warning(f"Unknown status for task {task_id}: {status}")
                time.sleep(CUCKOO_CONFIG['CHECK_INTERVAL'])
                retries += 1
        
        logger.error(f"Max retries reached for task {task_id}")
        return False
    
    def _get_task_status(self, task_id: int) -> Optional[str]:
        """Get task status from Cuckoo using /tasks/view/{id}"""
        try:
            # Fixed URL: removed /api prefix
            response = self.session.get(f'{self.base_url}/tasks/view/{task_id}')
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    
                    # Cuckoo returns task info with status field
                    if isinstance(result, dict):
                        # Check for direct status field
                        if 'status' in result:
                            return result['status']
                        
                        # Check for task object with status
                        if 'task' in result and isinstance(result['task'], dict):
                            return result['task'].get('status')
                    
                    logger.error(f"Unexpected response format for task {task_id}: {result}")
                    return None
                    
                except ValueError as e:
                    logger.error(f"Failed to parse JSON response for task {task_id}: {e}")
                    return None
            else:
                logger.warning(f"Status check failed for task {task_id}: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting status for task {task_id}: {str(e)}")
            return None
    
    # def _get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
    #     # Add delay to ensure report generation is complete
    #     logger.info("Waiting for report generation to complete...")
    #     time.sleep(30)  # Wait 15 seconds

    #     """Get JSON analysis report from Cuckoo using /tasks/report/{id}/json"""
    #     try:
    #         # Fixed URL: removed /api prefix
    #         response = self.session.get(f'{self.base_url}/tasks/report/{task_id}/json')
            
    #         if response.status_code == 200:
    #             try:
    #                 report = response.json()
    #                 logger.debug(f"Successfully retrieved report for task {task_id}")
    #                 return report
    #             except ValueError as e:
    #                 logger.error(f"Failed to parse JSON report for task {task_id}: {e}")
    #                 return None
    #         else:
    #             logger.error(f"Failed to get report for task {task_id}: HTTP {response.status_code}")
    #             logger.error(f"Response: {response.text}")
    #             return None
                
    #     except Exception as e:
    #         logger.error(f"Error getting report for task {task_id}: {str(e)}")
    #         return None

    def _get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """Get JSON analysis report from Cuckoo using /tasks/report/{id}/json with retry logic"""
        max_report_retries = 10  # Try up to 10 times
        report_retry_interval = 15  # Wait 15 seconds between retries
        
        for attempt in range(max_report_retries):
            try:
                logger.info(f"Attempting to retrieve report for task {task_id} (attempt {attempt + 1}/{max_report_retries})")
                
                response = self.session.get(f'{self.base_url}/tasks/report/{task_id}/json')
                
                if response.status_code == 200:
                    try:
                        report = response.json()
                        logger.info(f"Successfully retrieved report for task {task_id}")
                        return report
                    except ValueError as e:
                        logger.warning(f"Failed to parse JSON report for task {task_id}: {e}")
                        if attempt < max_report_retries - 1:
                            logger.info(f"Retrying in {report_retry_interval} seconds...")
                            time.sleep(report_retry_interval)
                            continue
                        else:
                            return None
                elif response.status_code == 404:
                    # Report not ready yet
                    logger.info(f"Report not ready for task {task_id}, waiting {report_retry_interval}s...")
                    if attempt < max_report_retries - 1:
                        time.sleep(report_retry_interval)
                        continue
                    else:
                        logger.error(f"Report still not available after {max_report_retries} attempts")
                        return None
                else:
                    logger.error(f"Failed to get report for task {task_id}: HTTP {response.status_code}")
                    logger.error(f"Response: {response.text}")
                    if attempt < max_report_retries - 1:
                        time.sleep(report_retry_interval)
                        continue
                    else:
                        return None
                    
            except Exception as e:
                logger.error(f"Error getting report for task {task_id} (attempt {attempt + 1}): {str(e)}")
                if attempt < max_report_retries - 1:
                    time.sleep(report_retry_interval)
                    continue
                else:
                    return None
    
        logger.error(f"Failed to retrieve report for task {task_id} after {max_report_retries} attempts")
        return None
    
    def test_connection(self) -> bool:
        """Test connection to Cuckoo API"""
        try:
            # Try to get cuckoo status (fixed URL)
            response = self.session.get(f'{self.base_url}/cuckoo/status')
            if response.status_code == 200:
                logger.info("✓ Cuckoo connection successful via /cuckoo/status")
                return True
            
            # Fallback: try machines endpoint
            response = self.session.get(f'{self.base_url}/machines/list')
            if response.status_code == 200:
                logger.info("✓ Cuckoo connection successful via /machines/list")
                return True
            
            logger.error(f"Both connection tests failed. Status: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Cuckoo connection test failed: {str(e)}")
            return False


# Convenience function for direct use in flask_api.py
def analyze_file_with_cuckoo(file_path: str) -> Dict[str, Any]:
    """
    Convenience function to analyze a file with Cuckoo.
    Use this directly in your Flask API
    
    Args:
        file_path (str): Path to the executable file
        
    Returns:
        dict: Cuckoo analysis report
        
    Raises:
        CuckooAnalysisError: If analysis fails
    """
    client = CuckooClient()
    return client.submit_file_and_wait(file_path)


def test_file_analysis(file_path: str):
    """
    Test function to demonstrate full Cuckoo analysis workflow
    
    Args:
        file_path (str): Path to the executable file to analyze
    """
    print(f"\n{'='*60}")
    print(f"TESTING CUCKOO ANALYSIS WITH FILE: {os.path.basename(file_path)}")
    print(f"{'='*60}")
    
    try:
        # Test connection first
        client = CuckooClient()
        print("\n1. Testing Cuckoo connection...")
        if not client.test_connection():
            print("✗ Cuckoo connection failed - cannot proceed")
            return
        
        print("✓ Cuckoo connection successful\n")
        
        # Validate file exists
        if not os.path.exists(file_path):
            print(f"✗ File not found: {file_path}")
            return
        
        file_size = os.path.getsize(file_path)
        print(f"2. File validation:")
        print(f"   - File: {file_path}")
        print(f"   - Size: {file_size:,} bytes")
        print(f"   - Max allowed: {CUCKOO_CONFIG['FILE_SIZE_LIMIT']:,} bytes")
        
        if file_size > CUCKOO_CONFIG['FILE_SIZE_LIMIT']:
            print("✗ File too large")
            return
        
        print("✓ File validation passed\n")
        
        # Start analysis
        print("3. Starting Cuckoo analysis...")
        print(f"   - Timeout: {CUCKOO_CONFIG['ANALYSIS_TIMEOUT']} seconds")
        print(f"   - Check interval: {CUCKOO_CONFIG['CHECK_INTERVAL']} seconds")
        print("   - This may take several minutes...\n")
        
        # Submit and wait for analysis
        report = client.submit_file_and_wait(file_path)
        
        print("\n4. Analysis Results:")
        print("✓ Analysis completed successfully!")
        
        # Display report summary
        if report:
            print(f"\n5. Report Summary:")
            print(f"   - Report type: {type(report).__name__}")
            print(f"   - Report keys: {len(report.keys()) if isinstance(report, dict) else 'N/A'}")
            
            if isinstance(report, dict):
                # Show main report sections
                main_keys = list(report.keys())[:10]  # First 10 keys
                print(f"   - Main sections: {main_keys}")
                
                # Show specific important fields if they exist
                important_fields = ['info', 'target', 'summary', 'signatures', 'behavior']
                found_fields = [key for key in important_fields if key in report]
                if found_fields:
                    print(f"   - Important sections found: {found_fields}")
                
                # Show signature count if available
                if 'signatures' in report and isinstance(report['signatures'], list):
                    print(f"   - Signatures detected: {len(report['signatures'])}")
                
                # Show target info if available
                if 'target' in report and isinstance(report['target'], dict):
                    target = report['target']
                    if 'file' in target and isinstance(target['file'], dict):
                        file_info = target['file']
                        print(f"   - Target file: {file_info.get('name', 'Unknown')}")
                        print(f"   - File size: {file_info.get('size', 'Unknown')} bytes")
                        print(f"   - MD5: {file_info.get('md5', 'Unknown')}")
        
        # Optionally save report to file
        report_file = f"cuckoo_report_{int(time.time())}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n6. Report saved to: {report_file}")
        except Exception as e:
            print(f"\n6. Could not save report: {e}")
        
        print(f"\n{'='*60}")
        print("TEST COMPLETED SUCCESSFULLY!")
        print(f"{'='*60}\n")
        
    except CuckooAnalysisError as e:
        print(f"\n✗ Cuckoo Analysis Error: {e}")
        print("Check the logs above for more details.")
    except Exception as e:
        print(f"\n✗ Unexpected Error: {e}")
        print("Check the logs above for more details.")


# Example usage for testing
# if __name__ == "__main__":
#     import sys
    
#     # Setup logging for testing
#     logging.basicConfig(
#         level=logging.DEBUG,  # Changed to DEBUG for more detailed output
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
#     )
    
#     print("CUCKOO CLIENT TESTING UTILITY")
#     print("=" * 40)
    
#     # Basic connection test
#     print("\nBasic Connection Test:")
#     client = CuckooClient()
#     if client.test_connection():
#         print("✓ Cuckoo connection successful")
#     else:
#         print("✗ Cuckoo connection failed")
#         print("Please check your Cuckoo configuration and try again.")
#         sys.exit(1)
    
#     # File analysis test
#     if len(sys.argv) > 1:
#         # File path provided as command line argument
#         test_file = sys.argv[1]
#         test_file_analysis(test_file)
#     else:
#         # Prompt user for file path
#         print("\nTo test file analysis, provide a file path:")
#         print("Usage: python cuckoo_client.py <path_to_executable>")
#         print("\nExample:")
#         print("  python cuckoo_client.py /path/to/test.exe")
#         print("  python cuckoo_client.py C:\\path\\to\\test.exe")
        
#         # Interactive mode
#         while True:
#             try:
#                 file_path = input("\nEnter file path (or 'quit' to exit): ").strip()
#                 if file_path.lower() in ['quit', 'exit', 'q']:
#                     break
#                 if file_path:
#                     test_file_analysis(file_path)
#             except KeyboardInterrupt:
#                 print("\nExiting...")
#                 break