import math
import string
from collections import Counter

ALLOWED_CHARS = set(string.ascii_lowercase + string.digits)

FEATURE_NAMES = [
    "domain_length",
    "domain_num_of_unique_char",
    "domain_num_of_unique_letters",
    "domain_num_of_unique_numbers",
    "ratio_of_letters_of_domain_name",
    "ratio_of_numbers_of_domain_name",
    "ratio_of_unique_letters_to_num_of_unique_characters",
    "ratio_of_unique_numbers_to_num_of_unique_characters",
    "entropy",
    "vowel_consonant_ratio",
    "dict_ratio",
]


def shannon_entropy(domain):
    counts = Counter(domain)
    return -sum((freq / len(domain)) * math.log2(freq / len(domain)) for freq in counts.values())


def vowel_consonant_ratio(domain):
    letters = [c for c in domain.lower() if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")
    consonants = sum(1 for c in letters if c not in "aeiou")
    return vowels / (consonants + 1e-6)


def simple_dict_ratio(domain):
    domain_letters = "".join([c for c in domain.lower() if c.isalpha()])
    common_patterns = ["the", "shop", "news", "tech", "web", "cloud", "data"]
    matches = sum(1 for p in common_patterns if p in domain_letters)
    return matches / max(1, len(common_patterns))


def extract_features(domain):
    # IMPORTANT: use FULL domain (MATLAB-compatible)
    name = domain.split(".")[0].lower()

    length = len(name)

    filtered = [c for c in name if c in ALLOWED_CHARS]
    unique_chars = len(set(filtered))

    letters = [c for c in name if c.isalpha()]
    digits = [c for c in name if c.isdigit()]

    unique_letters = len(set(letters))
    unique_digits = len(set(digits))

    num_letters = len(letters)
    num_digits = len(digits)

    # Ratios (exact MATLAB equivalent)
    ratio_letters = num_letters / length if length > 0 else 0
    ratio_digits = num_digits / length if length > 0 else 0

    ratio_unique_letters = unique_letters / unique_chars if unique_chars > 0 else 0
    ratio_unique_digits = unique_digits / unique_chars if unique_chars > 0 else 0

    # New features (aligned with same definition)
    entropy = shannon_entropy(name)
    vcr = vowel_consonant_ratio(name)
    dict_ratio = simple_dict_ratio(name)

    return [
        length,
        unique_chars,
        unique_letters,
        unique_digits,
        ratio_letters,
        ratio_digits,
        ratio_unique_letters,
        ratio_unique_digits,
        entropy,
        vcr,
        dict_ratio,
    ]
