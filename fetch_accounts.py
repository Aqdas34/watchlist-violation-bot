#!/usr/bin/env python3
import argparse
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

import requests

ENDPOINT = "api/card/recharge/task/list"


def norm_api_base(api_base: str) -> str:
    api_base = api_base.strip()
    if not api_base.endswith("/"):
        api_base += "/"
    return api_base


def clean_token(token: str) -> str:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    return token


def ms_to_dt_str(ms: Any) -> str:
    """Convert epoch milliseconds to 'YYYY-MM-DD HH:MM:SS'. Return '' if invalid."""
    try:
        if ms is None or ms == "":
            return ""
        ms_int = int(ms)
        return datetime.fromtimestamp(ms_int / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "X-Source": "panel",
        "Connection": "close",
    })
    return s


def fetch_page(url: str, page: int, limit: int, token: str, timeout: int) -> Tuple[int, Dict[str, Any]]:
    # session per thread (thread-safe)
    s = make_session(token)
    print(f"[+] Fetching page {page}")
    r = s.post(url, json={"page": page, "limit": limit}, timeout=timeout)
    r.raise_for_status()
    return page, r.json()


def extract_rows(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = resp.get("data") or {}
    rows = data.get("rows") or data.get("list") or []
    if not isinstance(rows, list):
        return []
    return rows


def is_last_page(resp: Dict[str, Any]) -> bool:
    data = resp.get("data") or {}
    return bool(data.get("lastPage", False))


def parse_remaining_day(val: Any) -> Optional[float]:
    try:
        if val is None or val == "":
            return None
        return float(val)
    except Exception:
        return None


def fetch_all_accounts_to_csv(
    token: str,
    out_csv: str,
    api_base: str,
    limit: int,
    threads: int,
    timeout: int,
    delay: float,
    dedupe: bool,
):
    token = clean_token(token)
    api_base = norm_api_base(api_base)
    url = api_base + ENDPOINT

    print("[*] Starting fetch...")
    print(f"[*] URL: {url}")
    print(f"[*] Threads: {threads}, limit: {limit}")
    print("[*] Filter: only remainingDay > 0 will be saved")

    all_rows_out: List[Dict[str, Any]] = []
    stop_after_page: Optional[int] = None

    current_page = 1
    while True:
        batch = list(range(current_page, current_page + threads))
        print(f"\n[*] Dispatching pages {batch[0]} → {batch[-1]}")

        results: List[Tuple[int, Dict[str, Any]]] = []

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(fetch_page, url, p, limit, token, timeout): p for p in batch}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    page, data = fut.result()
                except Exception as e:
                    print(f"[!] ERROR page {p}: {e}")
                    print("[!] Stopping due to failure.")
                    results = []
                    break
                results.append((page, data))

        if not results:
            break

        results.sort(key=lambda x: x[0])
        empty_hit = False

        kept_this_batch = 0
        seen_this_batch = 0

        for page, data in results:
            rows = extract_rows(data)
            print(f"[✓] Page {page}: {len(rows)} rows")

            if len(rows) == 0:
                print(f"[!] Page {page} empty rows → pagination end.")
                empty_hit = True
                break

            if is_last_page(data):
                print(f"[!] Page {page} has lastPage=True → will stop after this page.")
                stop_after_page = page

            for r in rows:
                if not isinstance(r, dict):
                    continue

                seen_this_batch += 1

                # Email/account/name fallbacks
                account_email = r.get("email") or r.get("account") or r.get("name") or ""

                remaining_raw = r.get("remainingDay")
                remaining_float = parse_remaining_day(remaining_raw)

                # ✅ FILTER: only remainingDay > 0
                if remaining_float is None or remaining_float <= 1:
                    continue

                created_at_ms = r.get("createdAt")
                valid_util_ms = r.get("validUtil")

                all_rows_out.append({
                    "email": account_email,
                    "remainingDay": remaining_raw,
                    "remainingDay_float": remaining_float,
                    "status": r.get("status"),
                    "taskId": r.get("taskId"),
                    "createdAt_ms": created_at_ms,
                    "createdAt": ms_to_dt_str(created_at_ms),
                    "validUtil_ms": valid_util_ms,
                    "validUtil": ms_to_dt_str(valid_util_ms),
                    "rootGoodsName": r.get("rootGoodsName"),
                    "periodPlan": r.get("periodPlan"),
                    "brand": r.get("brand"),
                })
                kept_this_batch += 1

        print(f"[*] Batch rows seen: {seen_this_batch}, kept (remainingDay>0): {kept_this_batch}")
        print(f"[*] Total kept so far: {len(all_rows_out)}")

        if empty_hit:
            break

        if stop_after_page is not None and current_page + threads - 1 >= stop_after_page:
            break

        current_page += threads
        time.sleep(delay)

    # Optional dedupe by email
    if dedupe:
        print("[*] Deduplicating by email...")
        seen = set()
        deduped = []
        for row in all_rows_out:
            em = row.get("email") or ""
            if not em or em in seen:
                continue
            seen.add(em)
            deduped.append(row)
        all_rows_out = deduped
        print(f"[*] After dedupe: {len(all_rows_out)} rows")

    # Write CSV
    fieldnames = [
        "email",
        "remainingDay",
        "remainingDay_float",
        "status",
        "taskId",
        "createdAt_ms",
        "createdAt",
        "validUtil_ms",
        "validUtil",
        "rootGoodsName",
        "periodPlan",
        "brand",
    ]

    print(f"\n[*] Writing CSV: {out_csv}")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in all_rows_out:
            w.writerow(r)

    print(f"✅ Done. Total accounts saved (remainingDay>0): {len(all_rows_out)}")
    print(f"📁 Saved to: {out_csv}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--out", default="accounts.csv")
    ap.add_argument("--api-base", default="https://www.passhub.store/")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--threads", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--delay", type=float, default=0.25)
    ap.add_argument("--dedupe", action="store_true", help="keep only first row per email")
    args = ap.parse_args()

    fetch_all_accounts_to_csv(
        token=args.token,
        out_csv=args.out,
        api_base=args.api_base,
        limit=args.limit,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        dedupe=args.dedupe,
    )


if __name__ == "__main__":
    main()
