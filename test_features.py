# test_features.py
from features import extract_all_features

# Test with a clear phishing email
test_email = """
URGENT: Your PayPal account has been SUSPENDED!!!
Dear Customer, click here to verify: http://bit.ly/paypal-verify
"""

features = extract_all_features(test_email)
print(f"Features: {features}")
print(f"Number of non-zero features: {sum(1 for f in features if f > 0)}")