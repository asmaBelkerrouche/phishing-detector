# prepare_data.py - Converts raw emails to numerical features for training

import pandas as pd
from features import extract_all_features
import time
import os
import csv

print("=" * 60)
print("PREPARING DATA FOR AI TRAINING")
print("=" * 60)

# 1. Load dataset
print("\n1. LOADING DATASET...")
file_path = 'data/phishing.csv'

if not os.path.exists(file_path):
    print(f"   ERROR: File not found at {file_path}")
    exit(1)

# Try different CSV reading methods
print("   Attempting to read CSV...")
try:
    df = pd.read_csv(file_path, quoting=csv.QUOTE_ALL, on_bad_lines='skip')
    print("   Method 1 succeeded")
except:
    try:
        df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip')
        print("   Method 2 succeeded")
    except:
        try:
            df = pd.read_csv(file_path, header=None, names=['Email Text', 'Email Type'], on_bad_lines='skip')
            print("   Method 3 succeeded")
        except Exception as e:
            print(f"   All methods failed: {e}")
            exit(1)

print(f"   Loaded {len(df)} emails")
print(f"   Columns: {list(df.columns)}")

# 2. Show sample
print("\n2. SAMPLE DATA:")
print(df.head(3))

# 3. Identify text and label columns
print("\n3. COLUMN IDENTIFICATION:")
possible_text_cols = ['Email Text', 'text', 'body', 'content', df.columns[0]]
possible_label_cols = ['Email Type', 'label', 'type', 'class', df.columns[1] if len(df.columns) > 1 else df.columns[0]]

text_col = next((col for col in possible_text_cols if col in df.columns), df.columns[0])
label_col = next((col for col in possible_label_cols if col in df.columns), 
                 df.columns[1] if len(df.columns) > 1 else df.columns[0])

print(f"   Using '{text_col}' for email text")
print(f"   Using '{label_col}' for labels")

# 4. Convert text labels to numbers
print("\n4. CONVERTING LABELS TO NUMBERS:")
unique_labels = df[label_col].unique()
print(f"   Unique label values: {unique_labels[:10]}")

def label_to_number(label):
    if pd.isna(label):
        return None
    label_str = str(label).lower()
    if 'phish' in label_str or 'spam' in label_str or '1' in label_str:
        return 1
    elif 'safe' in label_str or 'legit' in label_str or '0' in label_str:
        return 0
    return None

df['label_numeric'] = df[label_col].apply(label_to_number)

safe_count = sum(df['label_numeric'] == 0)
phish_count = sum(df['label_numeric'] == 1)
unknown_count = sum(df['label_numeric'].isna())

print(f"   Safe (0): {safe_count} emails")
print(f"   Phishing (1): {phish_count} emails")
print(f"   Unknown: {unknown_count} emails")

if unknown_count > 0:
    df = df.dropna(subset=['label_numeric'])
    print(f"   Removed {unknown_count} unknown labels")

# 5. Take sample (10k max)
print("\n5. TAKING SAMPLE...")
sample_size = min(10000, len(df))
df = df.sample(n=sample_size, random_state=42)
print(f"   Using {len(df)} emails for training")

# 6. Convert each email to features
print("\n6. CONVERTING EMAILS TO FEATURES...")
features_list = []
labels_list = []
start_time = time.time()
error_count = 0

for i, row in df.iterrows():
    if i % 1000 == 0 and i > 0:
        elapsed = time.time() - start_time
        print(f"   Processed {i}/{len(df)} emails... ({elapsed:.1f}s)")
    
    email_text = str(row[text_col]) if pd.notna(row[text_col]) else ""
    label = int(row['label_numeric'])
    
    try:
        features = extract_all_features(email_text)
        features_list.append(features)
        labels_list.append(label)
    except Exception as e:
        error_count += 1
        if error_count < 5:
            print(f"   Error on email {i}: {e}")
        continue

# 7. Results
elapsed = time.time() - start_time
print(f"\n7. CONVERSION COMPLETE!")
print(f"   Processed: {len(features_list)} emails")
print(f"   Errors: {error_count}")
print(f"   Time: {elapsed:.1f}s")

# 8. Save features
print("\n8. SAVING FEATURES...")
feature_names = [
    'urgent_words', 'generic_greeting', 'threat_words',
    'suspicious_links', 'ip_address_url', 'url_shortener',
    'suspicious_tld', 'misspelled_domain', 'personal_info_request',
    'spelling_mistakes', 'excessive_punctuation', 'dollar_signs',
    'attachment_mention', 'body_length', 'has_html'
]

features_df = pd.DataFrame(features_list, columns=feature_names)
features_df['label'] = labels_list
features_df.to_csv('data/email_features.csv', index=False)
print(f"   Saved to: data/email_features.csv")
print(f"   Shape: {features_df.shape}")

# 9. Show sample
print("\n9. SAMPLE CONVERTED DATA:")
print(features_df.head(10))

# 10. Statistics
print("\n10. DATASET STATISTICS:")
print(f"    Phishing (1): {sum(features_df['label']==1)}")
print(f"    Legit (0): {sum(features_df['label']==0)}")
if len(features_df) > 0:
    print(f"    Phishing ratio: {sum(features_df['label']==1)/len(features_df)*100:.1f}%")

# 11. Feature statistics
print("\n11. FEATURE STATISTICS (emails with each red flag):")
for col in feature_names:
    count = sum(features_df[col] > 0)
    pct = count/len(features_df)*100
    print(f"    {col}: {count} emails ({pct:.1f}%)")

print("\n" + "=" * 60)
print("PREPARE DATA COMPLETE! Ready for train_model.py")
print("=" * 60)