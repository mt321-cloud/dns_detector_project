FEATURE_NAMES_BINARY = [
    "length_diff",
    "levenshtein",
    "prefix_match",
    "suffix_match",
    "digit_ratio",
    "hyphen_count",
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


def extract_features(target, query):
    length_diff = abs(len(target) - len(query))
    lev = levenshtein(target, query)

    prefix_match = int(target[:3] == query[:3])
    suffix_match = int(target[-3:] == query[-3:])

    digit_ratio = sum(c.isdigit() for c in query) / len(query)
    hyphen_count = query.count("-")

    return [
        length_diff,
        lev,
        prefix_match,
        suffix_match,
        digit_ratio,
        hyphen_count,
    ]
