"""
Parses S3 access logs from logs.jeffreypratt.org/logs/,
looks up new IPs via ipinfo.io, and appends records to
logs.jeffreypratt.org/ipinfo/ips.csv.

Tracks processed log files in logs.jeffreypratt.org/ipinfo/processed_logs.json
so each file is only read once.
"""

import boto3
import csv
import io
import json
import os
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BUCKET = os.environ.get("LOG_BUCKET", "logs.jeffreypratt.org")
LOG_PREFIX = os.environ.get("LOG_PREFIX", "logs/")
CSV_KEY = os.environ.get("CSV_KEY", "ipinfo/ips.csv")
STATE_KEY = os.environ.get("STATE_KEY", "ipinfo/processed_logs.json")
IPINFO_TOKEN_PARAM = os.environ.get("IPINFO_TOKEN_PARAM", "/jeffreypratt/ipinfo_token")
IPINFO_RATE_LIMIT_DELAY = 0.05  # seconds between requests (~20 req/s, well under free tier)

# S3 access log: fields are space-separated; timestamp is [bracketed with a space inside],
# so the IP is the token immediately after the closing bracket.
IP_RE = re.compile(r"\[[^\]]+\] (\S+)")

s3 = boto3.client("s3", region_name="us-west-2")
ssm = boto3.client("ssm", region_name="us-west-2")

_ipinfo_token = None


def get_ipinfo_token():
    global _ipinfo_token
    if _ipinfo_token is None:
        resp = ssm.get_parameter(Name=IPINFO_TOKEN_PARAM, WithDecryption=True)
        _ipinfo_token = resp["Parameter"]["Value"]
    return _ipinfo_token


def load_state():
    """Return the set of already-processed S3 log keys."""
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=STATE_KEY)
        return set(json.loads(resp["Body"].read()))
    except s3.exceptions.NoSuchKey:
        return set()
    except Exception as e:
        print(f"Warning: could not load state file: {e}")
        return set()


def save_state(processed_keys):
    s3.put_object(
        Bucket=BUCKET,
        Key=STATE_KEY,
        Body=json.dumps(sorted(processed_keys)).encode(),
        ContentType="application/json",
    )


def load_known_ips():
    """Return the set of IPs already in ips.csv."""
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=CSV_KEY)
        reader = csv.reader(io.StringIO(resp["Body"].read().decode("utf-8")))
        return {row[0] for row in reader if row and not row[0].startswith("ip")}
    except s3.exceptions.NoSuchKey:
        return set()


def list_log_keys():
    """Yield all object keys under LOG_PREFIX."""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=LOG_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key != LOG_PREFIX:  # skip the prefix itself if it appears as a key
                yield key


def extract_ips_from_log(key):
    """Return the set of IPs found in a single log file."""
    ips = set()
    resp = s3.get_object(Bucket=BUCKET, Key=key)
    for line in resp["Body"].iter_lines():
        m = IP_RE.search(line.decode("utf-8", errors="replace"))
        if m:
            ip = m.group(1)
            if ip != "-":
                ips.add(ip)
    return ips


def lookup_ip(ip, token):
    """Call ipinfo.io and return a dict of fields, or None on failure."""
    url = f"https://ipinfo.io/{ip}?token={token}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        return {
            "ip": data.get("ip", ip),
            "hostname": data.get("hostname", "None") or "None",
            "city": data.get("city", "None") or "None",
            "region": data.get("region", "None") or "None",
            "country": data.get("country", "None") or "None",
            "postal": data.get("postal", "None") or "None",
            "timezone": data.get("timezone", "None") or "None",
        }
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} looking up {ip}")
        return None
    except Exception as e:
        print(f"Error looking up {ip}: {e}")
        return None


def append_records_to_csv(records):
    """Read existing CSV from S3, append new rows, write back."""
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=CSV_KEY)
        existing = resp["Body"].read().decode("utf-8")
    except s3.exceptions.NoSuchKey:
        existing = ""

    buf = io.StringIO()
    buf.write(existing)
    if existing and not existing.endswith("\n"):
        buf.write("\n")

    writer = csv.writer(buf, lineterminator="\n")
    for r in records:
        writer.writerow([r["ip"], r["hostname"], r["city"], r["region"], r["country"], r["postal"], r["timezone"]])

    s3.put_object(
        Bucket=BUCKET,
        Key=CSV_KEY,
        Body=buf.getvalue().encode("utf-8"),
        ContentType="text/csv",
    )


def lambda_handler(event, context):
    token = get_ipinfo_token()
    processed = load_state()
    known_ips = load_known_ips()

    # Stop processing new files when this many ms remain — enough time to write
    # partial results and exit cleanly before Lambda kills the process.
    TIME_BUFFER_MS = 30_000

    total_new_ips = 0
    new_log_files = 0

    for key in list_log_keys():
        if key in processed:
            continue

        if context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
            print("Approaching timeout — will resume on next invocation.")
            break

        print(f"Processing {key}")
        file_ips = extract_ips_from_log(key)
        new_ips = sorted(file_ips - known_ips)

        records = []
        interrupted = False
        for ip in new_ips:
            if context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
                # Partial results already written below; file stays unprocessed
                # so the remaining IPs are picked up next invocation.
                print(f"Timeout mid-file {key} — partial results saved, file will be reprocessed.")
                interrupted = True
                break
            info = lookup_ip(ip, token)
            if info:
                records.append(info)
                known_ips.add(ip)
            time.sleep(IPINFO_RATE_LIMIT_DELAY)

        if records:
            append_records_to_csv(records)
            total_new_ips += len(records)

        if interrupted:
            break

        processed.add(key)
        save_state(processed)
        new_log_files += 1

    print(f"Run complete: {total_new_ips} new IPs, {new_log_files} log files processed")
    return {"new_ips": total_new_ips, "new_log_files": new_log_files}
