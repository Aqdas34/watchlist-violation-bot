import csv

INPUT_FILE = "emails.csv"          # file that contains your quoted emails
OUTPUT_FILE = "arkodeitv_only.csv"
TARGET_DOMAIN = "arkodeitv.com"

filtered = []

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        email = line.strip().strip('"')
        if email.endswith("@" + TARGET_DOMAIN):
            filtered.append(email)

# write only arkodeitv.com emails, with double quotes
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    for email in filtered:
        writer.writerow([email])

print(f"Saved {len(filtered)} emails with domain {TARGET_DOMAIN} to {OUTPUT_FILE}")
