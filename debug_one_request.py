import requests
import json

API_URL = "https://www.passhub.store/api/card/recharge/task/list"

TOKEN = "Bearer 7c2b1f71-32b4-4be9-a1a3-74ba74615514"   # <-- paste your token here

payload = {
    "page": 1,
    "limit": 10
}

headers = {
    "Authorization": TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "User-Agent": "Mozilla/5.0",
    "X-Source": "panel",
}

print("[*] Sending request to:", API_URL)
print("[*] Payload:", payload)

r = requests.post(API_URL, json=payload, headers=headers, timeout=60)

print("\n================ RESPONSE =================")
print("Status Code:", r.status_code)

print("\n--- Response Headers ---")
for k, v in r.headers.items():
    print(f"{k}: {v}")

print("\n--- Raw Response Text (first 2000 chars) ---")
print(r.text[:2000])

print("\n--- JSON (pretty) ---")
try:
    data = r.json()
    print(json.dumps(data, indent=2, ensure_ascii=False)[:5000])  # show first 5000 chars
except Exception as e:
    print("Could not parse JSON:", e)
