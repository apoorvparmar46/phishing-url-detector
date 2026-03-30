import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # Length of URL
    features['url_length'] = len(url)

    # Has IP address instead of domain
    features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', urlparse(url).netloc) else 0

    # Count of special characters
    features['count_dots']    = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at']      = url.count('@')
    features['count_slash']   = url.count('/')
    features['count_question'] = url.count('?')
    features['count_equal']   = url.count('=')

    # Has HTTPS
    features['has_https'] = 1 if url.startswith('https') else 0

    # URL depth (number of path levels)
    features['url_depth'] = len([x for x in urlparse(url).path.split('/') if x])

    # Suspicious words
    suspicious = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'free', 'lucky']
    features['has_suspicious_word'] = 1 if any(word in url.lower() for word in suspicious) else 0

    return list(features.values())