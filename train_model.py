# train_model.py - Trains AI to detect phishing emails
# Splits data: 70% train, 15% validate, 15% test

import pandas as pd
import joblib
import os
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.utils import class_weight

print("=" * 70)
print("TRAINING PHISHING DETECTOR AI - WITH TRAIN/VALIDATE/TEST")
print("=" * 70)

# 1. Load features
print("\n1. LOADING FEATURES...")
df = pd.read_csv('data/email_features.csv')
print(f"   Loaded {len(df)} emails")
print(f"   Features: {df.shape[1]-1} columns")

# 2. Separate features (X) and labels (y)
X = df.drop('label', axis=1)
y = df['label']

print(f"\n2. DATA COMPOSITION:")
print(f"   Phishing: {sum(y==1)} ({sum(y==1)/len(y)*100:.1f}%)")
print(f"   Legit: {sum(y==0)} ({sum(y==0)/len(y)*100:.1f}%)")

# 3. First split: Train (70%) vs Temp (30%)
print("\n3. FIRST SPLIT: Train vs (Validation + Test)")
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)
print(f"   TRAIN set: {len(X_train)} emails ({len(X_train)/len(X)*100:.1f}%)")

# 4. Second split: Validation (15%) vs Test (15%)
print("\n4. SECOND SPLIT: Validation vs Test")
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)
print(f"   VALIDATION set: {len(X_val)} emails ({len(X_val)/len(X)*100:.1f}%)")
print(f"   TEST set: {len(X_test)} emails ({len(X_test)/len(X)*100:.1f}%)")

# 5. Handle class imbalance
print("\n5. CALCULATING CLASS WEIGHTS...")
weights = class_weight.compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
class_weights = dict(zip(np.unique(y_train), weights))
print(f"   Legit weight: {class_weights[0]:.2f}")
print(f"   Phishing weight: {class_weights[1]:.2f}")

# 6. Train model
print("\n6. TRAINING MODEL...")
print("   Using Random Forest with 200 trees")
start_time = time.time()

model = RandomForestClassifier(
    n_estimators=200, max_depth=15, min_samples_split=5,
    min_samples_leaf=2, random_state=42, n_jobs=-1,
    class_weight=class_weights, verbose=0
)
model.fit(X_train, y_train)
training_time = time.time() - start_time
print(f"   Training complete in {training_time:.2f} seconds")

# 7. Validation check
print("\n7. VALIDATION PHASE...")
val_pred = model.predict(X_val)
val_accuracy = accuracy_score(y_val, val_pred)
print(f"   Validation Accuracy: {val_accuracy*100:.2f}%")

# 8. Final test (unseen data)
print("\n8. FINAL TEST - Model has NEVER seen this data!")
test_pred = model.predict(X_test)
test_accuracy = accuracy_score(y_test, test_pred)
print(f"\n   FINAL TEST ACCURACY: {test_accuracy*100:.2f}%")
print(f"   (Tested on {len(X_test)} unseen emails)")

# 9. Detailed results
print("\n9. DETAILED PERFORMANCE REPORT (TEST SET):")
print(classification_report(y_test, test_pred, target_names=['Legit', 'Phishing'], zero_division=0))

# 10. Confusion matrix
print("\n10. CONFUSION MATRIX:")
cm = confusion_matrix(y_test, test_pred)
print(f"\n               PREDICTED")
print(f"               Legit  Phishing")
print(f"ACTUAL Legit    {cm[0,0]:5d}   {cm[0,1]:5d}  ← False Alarms")
print(f"       Phishing  {cm[1,0]:5d}   {cm[1,1]:5d}  ← Missed Attacks")

# Calculate rates
total_legit = cm[0,0] + cm[0,1]
total_phish = cm[1,0] + cm[1,1]
false_alarm_rate = cm[0,1] / total_legit * 100 if total_legit > 0 else 0
detection_rate = cm[1,1] / total_phish * 100 if total_phish > 0 else 0
print(f"\n   False Alarm Rate: {false_alarm_rate:.1f}%")
print(f"   Detection Rate: {detection_rate:.1f}%")

# 11. Feature importance
print("\n11. TOP 5 MOST IMPORTANT FEATURES:")
feature_names = X.columns.tolist()
importances = model.feature_importances_
top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:5]
for i, (name, importance) in enumerate(top_features, 1):
    print(f"    {i}. {name}: {importance*100:.1f}%")

# 12. Overfitting check
print("\n12. OVERFITTING CHECK:")
train_pred = model.predict(X_train)
train_accuracy = accuracy_score(y_train, train_pred)
print(f"   Training Accuracy: {train_accuracy*100:.2f}%")
print(f"   Validation Accuracy: {val_accuracy*100:.2f}%")
print(f"   Test Accuracy: {test_accuracy*100:.2f}%")

diff = train_accuracy - test_accuracy
if diff < 0.05:
    print(f"   GOOD: Small difference ({diff*100:.1f}%)")
elif diff < 0.10:
    print(f"   WARNING: Moderate difference ({diff*100:.1f}%)")
else:
    print(f"   BAD: Large difference ({diff*100:.1f}%)")

# 13. Save model
print("\n13. SAVING MODEL...")
os.makedirs('models', exist_ok=True)
model_path = 'models/phishing_detector.pkl'
joblib.dump(model, model_path)
print(f"    Model saved to: {model_path}")
print(f"    File size: {os.path.getsize(model_path) / 1024:.2f} KB")

# 14. Sample predictions
print("\n14. SAMPLE PREDICTIONS (First 10 test emails):")
print("   #  |  True Label  |  Predicted  |  Confidence  |  Result")
print("   " + "-" * 55)

for i in range(min(10, len(X_test))):
    true_label = y_test.iloc[i]
    pred_label = test_pred[i]
    proba = model.predict_proba(X_test.iloc[[i]])[0]
    confidence = proba[1] if pred_label == 1 else proba[0]
    
    true_str = "PHISHING" if true_label == 1 else "LEGIT"
    pred_str = "PHISHING" if pred_label == 1 else "LEGIT"
    result = "✓" if true_label == pred_label else "✗"
    
    print(f"   {i:2d}  |  {true_str:8s}  |  {pred_str:8s}  |  {confidence*100:5.1f}%    |  {result}")

# 15. Summary
print("\n" + "=" * 70)
print("TRAINING COMPLETE! SUMMARY:")
print("=" * 70)
print(f"Training data: {len(X_train)} emails")
print(f"Validation data: {len(X_val)} emails")
print(f"Test data: {len(X_test)} emails")
print(f"Test Accuracy: {test_accuracy*100:.2f}%")
print(f"Phishing Detection Rate: {detection_rate:.1f}%")
print(f"False Alarm Rate: {false_alarm_rate:.1f}%")
print("=" * 70)
print("Now run detect.py to scan new emails!")
print("=" * 70)