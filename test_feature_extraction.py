#!/usr/bin/env python3
"""
Test Dynamic Feature Extraction with Real Cuckoo JSON Report
Use your actual Cuckoo report file for testing
"""

import json
import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_cuckoo_report(report_path: str):
    """Load Cuckoo JSON report from file"""
    
    print(f"📂 Loading Cuckoo report: {report_path}")
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        print(f"✅ Report loaded successfully")
        
        # Show basic report info
        if 'info' in report:
            info = report['info']
            print(f"   Report ID: {info.get('id', 'unknown')}")
            print(f"   Package: {info.get('package', 'unknown')}")
            print(f"   Started: {info.get('started', 'unknown')}")
        
        # Show report sections
        sections = list(report.keys())
        print(f"   Report sections: {sections}")
        
        # Check sizes
        if 'behavior' in report:
            processes = report['behavior'].get('processes', [])
            print(f"   Processes: {len(processes)}")
        
        if 'network' in report:
            dns = report['network'].get('dns', [])
            http = report['network'].get('http', [])
            print(f"   Network - DNS: {len(dns)}, HTTP: {len(http)}")
        
        if 'strings' in report:
            print(f"   Strings: {len(report['strings'])}")
        
        if 'signatures' in report:
            print(f"   Signatures: {len(report['signatures'])}")
        
        if 'dropped' in report:
            print(f"   Dropped files: {len(report['dropped'])}")
        
        return report
        
    except FileNotFoundError:
        print(f"❌ File not found: {report_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        return None
    except Exception as e:
        print(f"❌ Error loading report: {e}")
        return None

def test_feature_extractor_with_report(report_path: str):
    """Test feature extractor with real Cuckoo report"""
    
    print("\n🧪 Testing Feature Extractor with Real Report")
    print("="*60)
    
    # Load report
    report = load_cuckoo_report(report_path)
    if not report:
        return False, None
    
    try:
        # Import feature extractor
        from utils.dynamic_feature_extractor import DynamicFeatureExtractor
        
        # Initialize with mapping
        mapping_file = "models/final_selected_feature_mapping.json"
        
        if not Path(mapping_file).exists():
            print(f"❌ Mapping file not found: {mapping_file}")
            print("Available mapping files:")
            for f in Path("models").glob("*.json"):
                print(f"   - {f}")
            return False, None
        
        extractor = DynamicFeatureExtractor(mapping_file)
        
        print(f"✅ Feature extractor loaded")
        print(f"✅ Expected features: {extractor.get_feature_count()}")
        
        # Extract features
        print(f"\n🔍 Extracting features from real report...")
        features_df = extractor.extract_features_from_cuckoo_json(report)
        
        print(f"\n📊 Feature Extraction Results:")
        print(f"   Output shape: {features_df.shape}")
        print(f"   Column count: {len(features_df.columns)}")
        
        # Count active features
        active_features_count = (features_df == 1).sum(axis=1).iloc[0]
        print(f"   Active features: {active_features_count}/{features_df.shape[1]}")
        print(f"   Sparsity: {(1 - active_features_count/features_df.shape[1])*100:.1f}% zeros")
        
        # Show active features
        if active_features_count > 0:
            active_columns = features_df.columns[(features_df == 1).iloc[0]]
            print(f"\n🎯 Active Features Found:")
            
            # Group by feature type
            feature_types = {}
            for col in active_columns:
                feature_name = extractor.feature_mapping.get(int(col), f"Unknown_{col}")
                feature_type = feature_name.split(':')[0] if ':' in feature_name else 'OTHER'
                
                if feature_type not in feature_types:
                    feature_types[feature_type] = []
                feature_types[feature_type].append((col, feature_name))
            
            # Show by type
            for ftype, features in feature_types.items():
                print(f"   {ftype}: {len(features)} features")
                for i, (fid, fname) in enumerate(features[:3]):  # Show first 3 of each type
                    print(f"     - {fid}: {fname}")
                if len(features) > 3:
                    print(f"     ... and {len(features)-3} more")
        else:
            print(f"⚠️  No features were activated - this might indicate an issue")
        
        # Validate dimensions
        if features_df.shape[1] == 150:
            print(f"\n✅ SUCCESS: Correct feature dimensions (150 features)")
            return True, features_df
        else:
            print(f"\n❌ ERROR: Expected 150 features, got {features_df.shape[1]}")
            return False, features_df
            
    except Exception as e:
        print(f"\n❌ Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def test_full_detector_with_report(report_path: str):
    """Test complete detector with real report"""
    
    print("\n🧪 Testing Full Detector Pipeline")
    print("="*50)
    
    # Load report
    report = load_cuckoo_report(report_path)
    if not report:
        return False
    
    try:
        # Import detector
        from dynamic_detector import load_dynamic_detector
        
        # Load detector
        print(f"Loading dynamic detector...")
        detector = load_dynamic_detector(
            models_dir="models/dynamic_ensemble",
            feature_mapping_file="models/final_selected_feature_mapping.json"
        )
        
        print(f"✅ Detector loaded")
        
        # Get model info
        model_info = detector.get_model_info()
        print(f"✅ Available models: {model_info.get('models', [])}")
        print(f"✅ Feature count: {model_info.get('feature_count', 0)}")
        
        # Make prediction
        print(f"\n🎯 Making prediction...")
        result = detector.predict_from_cuckoo_report(report)
        
        print(f"\n📊 PREDICTION RESULTS:")
        print(f"="*40)
        
        # Main prediction
        prediction = result.get('prediction', 'unknown')
        confidence = result.get('confidence', 0)
        print(f"🎯 Final Prediction: {prediction.upper()}")
        print(f"🎯 Confidence: {confidence:.4f} ({confidence*100:.1f}%)")
        
        # Probabilities
        probs = result.get('probabilities', {})
        print(f"\n📈 Probabilities:")
        print(f"   Benign: {probs.get('benign', 0):.4f} ({probs.get('benign', 0)*100:.1f}%)")
        print(f"   Ransomware: {probs.get('ransomware', 0):.4f} ({probs.get('ransomware', 0)*100:.1f}%)")
        
        # Individual models
        individual = result.get('individual_models', {})
        print(f"\n🤖 Individual Model Results:")
        successful_models = 0
        for model_name, model_result in individual.items():
            if 'error' in model_result:
                print(f"   ❌ {model_name}: {model_result['error']}")
            else:
                pred = model_result['prediction']
                conf = model_result['confidence']
                print(f"   ✅ {model_name}: {pred} ({conf:.4f})")
                successful_models += 1
        
        print(f"\n📊 Ensemble Summary:")
        print(f"   Successful models: {successful_models}/{len(individual)}")
        print(f"   Feature count processed: {result.get('feature_count', 0)}")
        
        # Voting details
        voting = result.get('voting_result', {})
        if voting:
            votes = voting.get('votes', [])
            print(f"   Votes: {votes} (0=Benign, 1=Ransomware)")
            print(f"   Majority threshold: {voting.get('majority_threshold', 0)}")
        
        # Check for errors
        if 'error' in result:
            print(f"\n❌ Prediction failed: {result['error']}")
            return False
        elif successful_models == 0:
            print(f"\n❌ No models succeeded - check individual errors above")
            return False
        else:
            print(f"\n✅ SUCCESS: Prediction completed successfully!")
            return True
            
    except Exception as e:
        print(f"\n❌ Full detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main execution"""
    
    if len(sys.argv) < 2:
        print("Usage: python test_with_real_cuckoo_report.py <path_to_cuckoo_report.json>")
        print("\nExample:")
        print("  python test_with_real_cuckoo_report.py reports/sample_123.json")
        print("  python test_with_real_cuckoo_report.py /path/to/cuckoo/analysis/1/reports/report.json")
        return
    
    report_path = sys.argv[1]
    
    print("🚀 Testing Dynamic Detection with Real Cuckoo Report")
    print("="*70)
    print(f"Report file: {report_path}")
    print("="*70)
    
    # Test 1: Feature Extraction
    extractor_success, features_df = test_feature_extractor_with_report(report_path)
    
    if not extractor_success:
        print(f"\n❌ Feature extraction failed - stopping here")
        print(f"💡 Check the mapping file path and report format")
        return
    
    # Test 2: Full Detection
    detector_success = test_full_detector_with_report(report_path)
    
    # Summary
    print(f"\n" + "="*70)
    print(f"🎯 FINAL TEST RESULTS")
    print(f"="*70)
    print(f"Report file: {report_path}")
    print(f"Feature extraction: {'✅ PASSED' if extractor_success else '❌ FAILED'}")
    print(f"Full detection: {'✅ PASSED' if detector_success else '❌ FAILED'}")
    
    if extractor_success and detector_success:
        print(f"\n🎉 ALL TESTS PASSED!")
        print(f"✅ Your dynamic detection system works with real Cuckoo reports")
        print(f"✅ Ready for production deployment")
    else:
        print(f"\n⚠️  Some tests failed")
        print(f"💡 Check error messages above for troubleshooting")

if __name__ == "__main__":
    main()