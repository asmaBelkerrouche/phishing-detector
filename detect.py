# detect.py - Uses trained AI to classify emails as phishing or legitimate

import joblib
import pandas as pd
from features import extract_all_features
import os

print("=" * 60)
print("PHISHING EMAIL DETECTOR")
print("=" * 60)

# Load the trained model
model_path = 'models/phishing_detector.pkl'
if not os.path.exists(model_path):
    print(f"Model not found at {model_path}")
    print("Please run train_model.py first")
    exit(1)

model = joblib.load(model_path)
print("AI Model loaded successfully!")

feature_names = [
    'urgent_words', 'generic_greeting', 'threat_words',
    'suspicious_links', 'ip_address_url', 'url_shortener',
    'suspicious_tld', 'misspelled_domain', 'personal_info_request',
    'spelling_mistakes', 'excessive_punctuation', 'dollar_signs',
    'attachment_mention', 'body_length', 'has_html'
]

while True:
    print("\n" + "-" * 60)
    print("1. Paste an email to analyze")
    print("2. Analyze sample test email")
    print("3. Exit")
    
    choice = input("\nChoose (1-3): ").strip()
    
    if choice == "3":
        print("\nGoodbye!")
        break
    
    elif choice == "2":
        email_text = """
        URGENT: Your PayPal account has been SUSPENDED!!!
        Dear Customer, we detected unusual activity.
        Click here to verify: http://bit.ly/paypal-verify
        If not verified within 24 hours, your account will be closed.
        """
        print("\nAnalyzing sample phishing email...")
    
    elif choice == "1":
        print("\nPaste your email (type 'DONE' on a new line when finished):")
        lines = []
        while True:
            line = input()
            if line == "DONE":
                break
            lines.append(line)
        email_text = "\n".join(lines)
    
    else:
        print("Invalid choice")
        continue
    
    # Extract features
    print("\nAnalyzing email...")
    features = extract_all_features(email_text)
    features_df = pd.DataFrame([features], columns=feature_names)
    
    # Show features extracted
    print("\nFeatures extracted:")
    active_features = []
    feature_indices = []
    for i, (name, value) in enumerate(zip(feature_names, features)):
        if value > 0:
            active_features.append(f"{name}: {value}")
            feature_indices.append(i)
    
    if active_features:
        for feat in active_features[:5]:
            print(f"   {feat}")
    else:
        print("   No suspicious features detected")
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]
    
    # False alarm check
    only_body_length = (len(feature_indices) == 1 and 13 in feature_indices)
    has_real_indicators = any([
        features[0] > 0, features[2] > 0, features[3] > 0,
        features[5] > 0, features[6] > 0, features[8] > 0
    ])
    
    # Show result
    print("\n" + "=" * 60)
    if prediction == 1:
        confidence = probabilities[1] * 100
        
        if only_body_length and confidence < 65 and not has_real_indicators:
            print(f"EMAIL APPEARS LEGITIMATE")
            print(f"   Confidence: {probabilities[0]*100:.1f}%")
            print(f"   (Low confidence phishing - likely false alarm)")
        else:
            if confidence > 80:
                level = "HIGH RISK"
            elif confidence > 60:
                level = "MEDIUM RISK"
            else:
                level = "LOW RISK"
            
            print(f"PHISHING DETECTED!")
            print(f"   Confidence: {confidence:.1f}%")
            print(f"   Risk Level: {level}")
    else:
        confidence = probabilities[0] * 100
        print(f"EMAIL APPEARS LEGITIMATE")
        print(f"   Confidence: {confidence:.1f}%")
    
    # Show top indicators
    if has_real_indicators:
        print("\nTop indicators:")
        importances = model.feature_importances_
        top_indices = sorted(range(len(importances)), key=lambda i: importances[i], reverse=True)[:3]
        for idx in top_indices:
            if features[idx] > 0:
                print(f"   • {feature_names[idx]}: {importances[idx]*100:.1f}% weight")
    
    print("=" * 60)