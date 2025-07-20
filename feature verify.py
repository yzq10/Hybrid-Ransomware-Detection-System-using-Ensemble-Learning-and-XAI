#!/usr/bin/env python3
"""
Quick test to verify dynamic detector works with 150 features
"""

def test_dynamic_detector():
    """Test the detector loads and outputs correct dimensions"""
    
    try:
        # Import your detector
        from dynamic_detector import load_dynamic_detector
        
        print("🧪 Testing Dynamic Detector with 150 Features")
        print("="*50)
        
        # Load detector with your mapping file
        detector = load_dynamic_detector(
            models_dir="models/dynamic_ensemble",  # Your model directory
            feature_mapping_file="models/final_selected_feature_mapping.json"  # Your mapping file
        )
        
        # Check feature count
        model_info = detector.get_model_info()
        feature_count = model_info.get('feature_count', 0)
        
        print(f"✓ Detector loaded successfully")
        print(f"✓ Feature count: {feature_count}")
        
        if feature_count == 150:
            print(f"✅ SUCCESS: Feature count matches expected 150!")
        else:
            print(f"❌ ERROR: Expected 150 features, got {feature_count}")
            return False
        
        # Test with dummy Cuckoo report
        dummy_report = {
            "behavior": {"processes": [], "summary": {}},
            "network": {"dns": [], "http": []},
            "strings": [],
            "signatures": [],
            "dropped": []
        }
        
        # Test prediction
        result = detector.predict_from_cuckoo_report(dummy_report)
        
        print(f"✓ Prediction test completed")
        print(f"✓ Prediction: {result.get('prediction', 'unknown')}")
        print(f"✓ Feature count in result: {result.get('feature_count', 0)}")
        
        if result.get('feature_count') == 150:
            print(f"✅ SUCCESS: All tests passed!")
            print(f"✅ Dynamic detector is ready for 150-feature models!")
            return True
        else:
            print(f"❌ ERROR: Feature extraction dimension mismatch")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

if __name__ == "__main__":
    success = test_dynamic_detector()
    if success:
        print(f"\n🎉 Your dynamic detector is ready!")
    else:
        print(f"\n⚠️  Please check the error messages above")