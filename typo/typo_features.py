FEATURE_NAMES = [
    "levenshtein",
    "normalized_levenshtein",
    "jaccard_similarity",
    "jaro_similarity",
    "length_diff",
    "prefix_match",
    "suffix_match",
    "digit_ratio",
    "hyphen_count",
    "dot_count",
    "tld_match",
]

ALLOWED_CLASSES = [
    "addition",
    "omission",
    "replacement",
    "transposition",
    "none",
    "subdomain",
    "homoglyph"
]


def levenshtein(a, b):
    n, m = len(a), len(b)

    if n > m:
        a, b = b, a
        n, m = m, n

    current = list(range(n + 1))

    for i in range(1, m + 1):
        previous, current = current, [i] + [0] * n

        for j in range(1, n + 1):
            add = previous[j] + 1
            delete = current[j - 1] + 1
            change = previous[j - 1]

            if a[j - 1] != b[i - 1]:
                change += 1

            current[j] = min(add, delete, change)

    return current[n]


def ngrams(s, n=3):
    return set([s[i:i + n] for i in range(len(s) - n + 1)])


def jaccard_similarity(a, b):
    a_ngrams = ngrams(a)
    b_ngrams = ngrams(b)

    if not a_ngrams or not b_ngrams:
        return 0

    return len(a_ngrams & b_ngrams) / len(a_ngrams | b_ngrams)


def jaro_similarity(s1, s2):
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)

    if len1 == 0 or len2 == 0:
        return 0

    match_distance = (max(len1, len2) // 2) - 1

    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)

        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue

            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    return (
        (matches / len1)
        + (matches / len2)
        + ((matches - transpositions // 2) / matches)
    ) / 3


def extract_features(target, query):
    lev = levenshtein(target, query)
    max_len = max(len(target), len(query))

    norm_lev = lev / max_len
    jaccard = jaccard_similarity(target, query)
    jaro = jaro_similarity(target, query)

    length_diff = len(target) - len(query)

    prefix_match = int(target[:3] == query[:3])
    suffix_match = int(target[-3:] == query[-3:])

    digit_ratio = sum(c.isdigit() for c in query) / len(query)
    hyphen_count = query.count("-")

    dot_count = query.count(".")
    tld_match = int(target.split(".")[-1] == query.split(".")[-1])

    return [
        lev,
        norm_lev,
        jaccard,
        jaro,
        length_diff,
        prefix_match,
        suffix_match,
        digit_ratio,
        hyphen_count,
        dot_count,
        tld_match,
    ]