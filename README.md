# phishing-detector

# I Built an AI That Detects Phishing Emails (And You Can Try It)

## 🎣 What Is This?

Ever gotten an email that just *felt* wrong? Maybe it said your PayPal account was "suspended" or there was "unusual activity" on your bank account. You know, the ones that try to panic you into clicking a shady link?

I got tired of almost falling for these, so I built an AI that does the detective work for me.

**This tool lets you paste any email, and it'll tell you:**
- ✅ "This looks safe" (with confidence %)
- 🔴 "This is probably phishing" (with confidence %)
- 🟡 "Hmm, suspicious but not sure" (medium risk)

No more second-guessing those sketchy emails!

---
## Dataset Source

The dataset used in this project is the **"Phishing Email Detection" dataset from Kaggle**. From Enron Corporation employees, with approximately 60% legitimate emails and 40% phishing emails.

The dataset is publicly available on Kaggle and can be accessed here:  
[https://www.kaggle.com/code/kirollosashraf/phishing-email-detection-using-deep-learning/input](https://www.kaggle.com/code/kirollosashraf/phishing-email-detection-using-deep-learning/input)

**File:** `Phishing_Email.csv` (52 MB)  
**Format:** CSV with columns "Email Text" and "Email Type"

---
## 🧠 How Does It Actually Work?

Think of it like training a cybersecurity intern. I showed it **18,650 real emails** – half legit, half phishing – and taught it to spot the patterns that give phishing away.

### The 15 Things It Checks in Every Email:

| What It Looks For | Why It Matters |
|-------------------|----------------|
| **Urgent words** | "URGENT", "IMMEDIATELY", "ASAP" – phishers love panic |
| **Generic greetings** | "Dear Customer" instead of your actual name |
| **Threats** | "Your account will be suspended/closed/deleted" |
| **Suspicious links** | Bit.ly, tinyurl, or links that hide where they really go |
| **IP address links** | Links like http://192.168.1.45/paypal – super sketchy |
| **Weird domains** | paypaI.com (with a capital i instead of l), amaz0n.com |
| **Personal info requests** | "Confirm your password/SSN/credit card" |
| **Spelling mistakes** | "recieved" instead of "received" – common in phishing |
| **Excessive punctuation** | "VERIFY NOW!!!" or "????" |
| **Money talk** | $ signs, especially if they're asking for it |
| **Attachments** | "Download this file" – often means malware |
| **HTML code** | Fancy formatting can hide malicious links |
| **Email length** | Surprisingly, longer emails are often more suspicious |

It's like having a paranoid friend who reads every email with you and points out all the red flags.

---

## Performance

Tested on 1,500 emails the AI had never seen before:
- **Accuracy:** 70%
- **Phishing caught:** 59%
- **False alarms:** 23% (legit emails flagged as phishing)


### Top 5 Most Important Features:
1. body_length - 27%
2. dollar_signs - 17%
3. urgent_words - 14%
4. attachment_mention - 9.5%
5. personal_info_request - 7%

## Installation

# Clone the repo
git clone https://github.com/asmaBelkerrouche/phishing-detector.git
cd phishing-detector

# Install dependencies
pip install pandas scikit-learn joblib numpy

# Prepare data and train the model
python prepare_data.py
python train_model.py

# Run the detector
python detect.py
