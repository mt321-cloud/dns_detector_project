import dnstwist
import csv
import random

INPUT_FILE = "./typo/tranco_KW6WW.csv"
OUTPUT_FILE = "./typo/typos_multiclass_dataset_2.csv"
N = 1000

i=0 
negatives_per_domain = 40

# fuzzer types to exclude
excluded = {
    "*original"
}

domains = []

# LOAD DOMAINS
with open(INPUT_FILE) as f:
    for line in f:
        rank, domain = line.strip().split(",")
        domains.append(domain.lower())

rows = []
seen = set()  # used to prevent duplicates

# GENERATE TYPOS
for domain in domains[:N]:
    
    print("Processing:", domain)
    i = 0
    
    fuzz = dnstwist.Fuzzer(domain)
    fuzz.generate()

    for perm in fuzz.domains:

        fuzzer = perm["fuzzer"]
        typo = perm["domain"].lower()

        # skip excluded fuzzers and original domain
        if fuzzer in excluded:
            continue

        key = (domain, typo)

        if key not in seen:
            rows.append([domain, typo, fuzzer])
            seen.add(key)
            i += 1
    
    print("  Generated typos:", i)
    
    # GENERATE NEGATIVE SAMPLES
    attempts = 0
    
    while attempts < negatives_per_domain:

        other = random.choice(domains)

        if other == domain:
            continue

        key = (domain, other)

        if key not in seen:

            rows.append([domain, other, "none"])
            seen.add(key)

            attempts += 1
    
    print("  Generated negative samples:", attempts)

# # GENERATE NEGATIVE SAMPLES

# for domain in domains[:N]:

#     attempts = 0

#     while attempts < i:

#         other = random.choice(domains)

#         if other == domain:
#             continue

#         key = (domain, other)

#         if key not in seen:

#             rows.append([domain, other, "none"])
#             seen.add(key)

#             attempts += 1
    
#     print("  Generated negative samples:", attempts)

# SAVE DATASET
with open(OUTPUT_FILE, "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "target_domain",
        "query_domain",
        "classification"
    ])

    writer.writerows(rows)

print("Dataset size:", len(rows))