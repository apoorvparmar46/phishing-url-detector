import re
import math
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
    'click', 'loan', 'win', 'review', 'country', 'stream',
}

SUSPICIOUS_WORDS = {
    'login', 'verify', 'secure', 'account', 'update', 'bank',
    'free', 'lucky', 'password', 'signin', 'confirm',
    'webscr', 'admin', 'wp-admin',
}


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_features(url):
    url = str(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    try:
        port = parsed.port
    except ValueError:
        port = None

    hostname_parts = hostname.split('.') if hostname else []
    tld = hostname_parts[-1].lower() if hostname_parts else ''
    path_tokens = [t for t in path.split('/') if t]

    url_len = len(url) or 1
    host_len = len(hostname) or 1

    f = {
        # lengths & structure
        'url_length':            len(url),
        'hostname_length':       len(hostname),
        'path_length':           len(path),
        'query_length':          len(query),
        'tld_length':            len(tld),
        'num_subdomains':        max(0, len(hostname_parts) - 2),
        'path_depth':            len(path_tokens),
        'longest_path_token':    max((len(t) for t in path_tokens), default=0),
        'num_path_tokens':       len(path_tokens),

        # special-character counts
        'count_dots':       url.count('.'),
        'count_hyphens':    url.count('-'),
        'count_underscore': url.count('_'),
        'count_slash':      url.count('/'),
        'count_question':   url.count('?'),
        'count_equal':      url.count('='),
        'count_at':         url.count('@'),
        'count_ampersand':  url.count('&'),
        'count_percent':    url.count('%'),
        'count_hash':       url.count('#'),
        'count_tilde':      url.count('~'),
        'count_plus':       url.count('+'),
        'count_asterisk':   url.count('*'),

        # character composition
        'digit_count':          sum(c.isdigit() for c in url),
        'letter_count':         sum(c.isalpha() for c in url),
        'digit_ratio':          sum(c.isdigit() for c in url) / url_len,
        'hostname_digit_ratio': sum(c.isdigit() for c in hostname) / host_len,
        'hostname_entropy':     _shannon_entropy(hostname),
        'path_entropy':         _shannon_entropy(path),

        # security signals
        'has_https':                int(parsed.scheme == 'https'),
        'has_ip':                   int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))),
        'has_port':                 int(port is not None),
        'has_at_symbol':            int('@' in url),
        'has_double_slash_in_path': int('//' in path),
        'suspicious_tld':           int(tld in SUSPICIOUS_TLDS),
        'suspicious_word_count':    sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
    }
    return list(f.values())


FEATURE_NAMES = [
    'url_length', 'hostname_length', 'path_length', 'query_length', 'tld_length',
    'num_subdomains', 'path_depth', 'longest_path_token', 'num_path_tokens',
    'count_dots', 'count_hyphens', 'count_underscore', 'count_slash',
    'count_question', 'count_equal', 'count_at', 'count_ampersand',
    'count_percent', 'count_hash', 'count_tilde', 'count_plus', 'count_asterisk',
    'digit_count', 'letter_count', 'digit_ratio', 'hostname_digit_ratio',
    'hostname_entropy', 'path_entropy',
    'has_https', 'has_ip', 'has_port', 'has_at_symbol',
    'has_double_slash_in_path', 'suspicious_tld', 'suspicious_word_count',
]