# features.py - Converts emails into numerical features for AI

import re
import urllib.parse
from urllib.parse import urlparse

def has_urgent_words(text):
    urgent_words = [
        'urgent', 'immediately', 'asap', 'warning', 'important',
        'alert', 'attention', 'critical', 'deadline', 'expires',
        'suspended', 'locked', 'limited', 'restricted', 'blocked',
        'verify now', 'act now', 'click here', 'do it now'
    ]
    text_lower = str(text).lower()
    for word in urgent_words:
        if word in text_lower:
            return 1
    return 0

def has_generic_greeting(text):
    generic_greetings = [
        'dear customer', 'dear user', 'dear member', 'dear client',
        'valued customer', 'valued member', 'hello customer',
        'hello user', 'greetings', 'to whom it may concern'
    ]
    text_lower = str(text).lower()
    for greeting in generic_greetings:
        if greeting in text_lower:
            return 1
    return 0

def has_ip_address_url(text):
    ip_pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'
    if re.search(ip_pattern, str(text)):
        return 1
    return 0

def has_url_shortener(text):
    shorteners = [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 't.co',
        'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'bitly.com'
    ]
    text_lower = str(text).lower()
    for shortener in shorteners:
        if shortener in text_lower:
            return 1
    return 0

def count_suspicious_links(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, str(text))
    
    suspicious_count = 0
    for url in urls:
        if has_ip_address_url(url) or has_url_shortener(url):
            suspicious_count += 1
    return min(suspicious_count, 5)

def has_suspicious_tld(text):
    suspicious_tlds = [
        '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.xyz',
        '.top', '.club', '.online', '.site', '.work', '.date'
    ]
    text_lower = str(text).lower()
    for tld in suspicious_tlds:
        if tld in text_lower and 'http' in text_lower:
            return 1
    return 0

def has_misspelled_domain(text):
    misspellings = ['paypaI', 'paypall', 'paypai', 'pay-pal',
                   'amaz0n', 'amazom', 'amazn', 'ama-zon',
                   'appIe', 'appple', 'aple',
                   'micros0ft', 'micr0soft', 'micro-soft',
                   'googIe', 'gooogle', 'g00gle',
                   'faceb00k', 'face-book', 'facebo0k']
    text_lower = str(text).lower()
    for wrong in misspellings:
        if wrong in text_lower:
            return 1
    return 0

def has_spelling_mistakes(text):
    common_mistakes = [
        'recieved', 'recieve', 'acheive', 'seperate', 'definately',
        'goverment', 'occured', 'occuring', 'untill',
        'wich', 'accomodate', 'acommodate', 'priviledge'
    ]
    text_lower = str(text).lower()
    mistakes_found = 0
    for mistake in common_mistakes:
        if mistake in text_lower:
            mistakes_found += 1
    return min(mistakes_found, 3)

def has_excessive_punctuation(text):
    text_str = str(text)
    if '!!!' in text_str or '???' in text_str:
        return 1
    if len(text_str) > 50:
        caps_ratio = sum(1 for c in text_str if c.isupper()) / len(text_str)
        if caps_ratio > 0.3:
            return 1
    return 0

def has_attachment_mention(text):
    attachment_words = ['attach', 'download', 'open file', 'click file', 'view attachment']
    text_lower = str(text).lower()
    for word in attachment_words:
        if word in text_lower:
            return 1
    return 0

def body_length(text):
    return min(len(str(text)) // 100, 10)

def has_html(text):
    text_lower = str(text).lower()
    if '<html' in text_lower or '<body' in text_lower or '<div' in text_lower:
        return 1
    return 0

def has_threat_words(text):
    threat_words = [
        'suspend', 'terminate', 'close', 'delete', 'remove',
        'cancel', 'block', 'restrict', 'disable', 'deactivate',
        'legal action', 'lawsuit'
    ]
    text_lower = str(text).lower()
    for word in threat_words:
        if word in text_lower and ('account' in text_lower or 'access' in text_lower):
            return 1
    return 0

def has_personal_info_request(text):
    info_requests = [
        'ssn', 'social security', 'credit card number', 'cvv', 'pin',
        'password', 'passcode', 'bank account number', 'routing number',
        'mother\'s maiden name', 'driver\'s license'
    ]
    asking_phrases = ['enter your', 'provide your', 'send us your', 'confirm your', 'verify your']
    
    text_lower = str(text).lower()
    for request in info_requests:
        if request in text_lower:
            for phrase in asking_phrases:
                if phrase in text_lower:
                    return 1
    return 0

def has_dollar_signs(text):
    text_str = str(text)
    if '$' in text_str or '€' in text_str or '£' in text_str:
        receipt_indicators = ['receipt', 'statement', 'total', 'summary', 'bill']
        text_lower = text_str.lower()
        for indicator in receipt_indicators:
            if indicator in text_lower:
                return 0
        return min(text_str.count('$') + text_str.count('€') + text_str.count('£'), 3)
    return 0

def has_legitimate_domain(text):
    legitimate_domains = [
        'amazon.com', 'netflix.com', 'linkedin.com', 'paypal.com',
        'chase.com', 'wellsfargo.com', 'usps.com', 'fedex.com',
        'microsoft.com', 'apple.com', 'google.com'
    ]
    text_lower = str(text).lower()
    for domain in legitimate_domains:
        if domain in text_lower and 'http' in text_lower:
            if f'https://www.{domain}' in text_lower or f'http://www.{domain}' in text_lower:
                return 0
            elif f'https://{domain}' in text_lower or f'http://{domain}' in text_lower:
                return 0
    return 1

def extract_all_features(email_text):
    features = []
    features.append(has_urgent_words(email_text))
    features.append(has_generic_greeting(email_text))
    features.append(has_threat_words(email_text))
    features.append(count_suspicious_links(email_text))
    features.append(has_ip_address_url(email_text))
    features.append(has_url_shortener(email_text))
    features.append(has_suspicious_tld(email_text))
    features.append(has_misspelled_domain(email_text))
    features.append(has_personal_info_request(email_text))
    features.append(has_spelling_mistakes(email_text))
    features.append(has_excessive_punctuation(email_text))
    features.append(has_dollar_signs(email_text))
    features.append(has_attachment_mention(email_text))
    features.append(body_length(email_text))
    features.append(has_html(email_text))
    return features

if __name__ == "__main__":
    test_email = """
    URGENT: Your PayPal account has been SUSPENDED!!!
    Dear Customer, click here to verify: http://bit.ly/paypal-verify
    """
    features = extract_all_features(test_email)
    print(f"Extracted {len(features)} features")
    print(f"Feature vector: {features}")