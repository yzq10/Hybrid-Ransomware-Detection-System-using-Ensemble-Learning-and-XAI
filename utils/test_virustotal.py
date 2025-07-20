#!/usr/bin/env python3
"""
VirusTotal Signature Testing Script
Interactive script to test the updated direct logic VirusTotal checking
"""

import os
import sys
import logging
from pathlib import Path

# Add the utils directory to the path so we can import virustotal_check
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'utils'))

try:
    from virustotal_check import analyze_file_signature
except ImportError as e:
    print(f"❌ Error importing virustotal_check: {e}")
    print("Make sure you're running this script from the correct directory")
    print("Expected structure: project_root/utils/virustotal_check.py")
    sys.exit(1)

# Configure logging for testing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def print_header():
    """Print a nice header for the test script"""
    print("=" * 60)
    print("🔍 VIRUSTOTAL SIGNATURE TESTING SCRIPT")
    print("=" * 60)
    print("This script tests the updated direct logic VirusTotal checking")
    print("Expected results:")
    print("  • UNKNOWN: File not in VT database (modified signatures)")
    print("  • BENIGN: Majority of engines found it clean")
    print("  • RANSOMWARE: Majority of engines detected threats")
    print("=" * 60)

def format_result(decision):
    """Format the decision with appropriate emoji and color"""
    if decision == 'unknown':
        return "🔍 UNKNOWN"
    elif decision == 'benign':
        return "✅ BENIGN"
    elif decision == 'malicious':
        return "⚠️  RANSOMWARE"
    elif decision == 'error':
        return "❌ ERROR"
    else:
        return f"❓ {decision.upper()}"

def print_detection_breakdown(result):
    """Print detailed breakdown of VirusTotal detection results"""
    if 'detection_counts' in result:
        counts = result['detection_counts']
        print("\n📊 VIRUSTOTAL DETECTION BREAKDOWN:")
        print(f"  Malicious:   {counts['malicious']:3d} engines")
        print(f"  Suspicious:  {counts['suspicious']:3d} engines")
        print(f"  Harmless:    {counts['harmless']:3d} engines")
        print(f"  Undetected:  {counts['undetected']:3d} engines")
        print(f"  " + "-" * 30)
        print(f"  Threat Total: {counts['threat_total']:3d} engines")
        print(f"  Clean Total:  {counts['clean_total']:3d} engines")
        
        # Show the decision logic
        if counts['threat_total'] > counts['clean_total']:
            print(f"  ➜ Decision: {counts['threat_total']} > {counts['clean_total']} = MALICIOUS")
        elif counts['clean_total'] > counts['threat_total']:
            print(f"  ➜ Decision: {counts['clean_total']} > {counts['threat_total']} = BENIGN")
        else:
            print(f"  ➜ Decision: {counts['clean_total']} = {counts['threat_total']} = TIE (BENIGN)")

def print_file_info(result):
    """Print file hash and scan information"""
    if result.get('file_hash'):
        print(f"\n🔑 FILE HASH: {result['file_hash']}")
    
    if result.get('scan_date'):
        print(f"📅 SCAN DATE: {result['scan_date']}")
    
    if result.get('stage'):
        print(f"🏷️  STAGE: {result['stage']}")

def test_single_file(file_path):
    """Test a single file and display results"""
    print(f"\n🔍 Testing file: {file_path}")
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ ERROR: File not found: {file_path}")
        return False
    
    # Check if it's a file (not directory)
    if not os.path.isfile(file_path):
        print(f"❌ ERROR: Path is not a file: {file_path}")
        return False
    
    print("⏳ Analyzing file signature...")
    
    try:
        # Run the signature analysis
        result = analyze_file_signature(file_path)
        
        # Print main result
        print(f"\n{format_result(result['decision'])} - {result['reason']}")
        print(f"🎯 CONFIDENCE: {result['confidence']:.1%}")
        print(f"🎬 ACTION: {result['action']}")
        
        # Print detailed breakdown
        print_detection_breakdown(result)
        
        # Print file information
        print_file_info(result)
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR during analysis: {str(e)}")
        return False

def interactive_mode():
    """Interactive mode - prompt for file paths"""
    print_header()
    
    while True:
        print("\n" + "─" * 60)
        file_path = input("📁 Enter file path to test (or 'quit' to exit): ").strip()
        
        if file_path.lower() in ['quit', 'exit', 'q']:
            print("👋 Goodbye!")
            break
        
        if not file_path:
            print("❌ Please enter a valid file path")
            continue
        
        # Expand user path (~) if present
        file_path = os.path.expanduser(file_path)
        
        # Test the file
        success = test_single_file(file_path)
        
        if success:
            print("\n✅ Test completed successfully!")
        else:
            print("\n❌ Test failed!")
        
        # Ask if user wants to test another file
        while True:
            continue_test = input("\n🔄 Test another file? (y/n): ").strip().lower()
            if continue_test in ['y', 'yes']:
                break
            elif continue_test in ['n', 'no']:
                print("👋 Goodbye!")
                return
            else:
                print("❌ Please enter 'y' or 'n'")

def batch_mode(file_paths):
    """Batch mode - test multiple files"""
    print_header()
    print(f"🔄 Testing {len(file_paths)} files in batch mode...")
    
    results = []
    
    for i, file_path in enumerate(file_paths, 1):
        print(f"\n📋 [{i}/{len(file_paths)}] Testing: {file_path}")
        success = test_single_file(file_path)
        results.append(success)
    
    # Summary
    successful = sum(results)
    failed = len(results) - successful
    
    print(f"\n📊 BATCH TEST SUMMARY:")
    print(f"  ✅ Successful: {successful}")
    print(f"  ❌ Failed: {failed}")
    print(f"  📈 Success Rate: {(successful/len(results)*100):.1f}%")

def main():
    """Main function"""
    if len(sys.argv) > 1:
        # Batch mode - files provided as arguments
        file_paths = sys.argv[1:]
        batch_mode(file_paths)
    else:
        # Interactive mode
        interactive_mode()

if __name__ == "__main__":
    main()