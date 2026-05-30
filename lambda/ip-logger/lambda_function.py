"""
Parses S3 access logs from logs.jeffreypratt.org/logs/,
looks up new IPs via ipinfo.io, appends records to
logs.jeffreypratt.org/ipinfo/ips.csv, and emails a per-run
report showing every request seen in newly processed log files.

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
REPORT_EMAIL_TO = os.environ.get("REPORT_EMAIL_TO", "")
REPORT_EMAIL_FROM = os.environ.get("REPORT_EMAIL_FROM", "")
SES_REGION = os.environ.get("SES_REGION", "us-east-1")
IPINFO_RATE_LIMIT_DELAY = 0.05  # seconds between requests (~20 req/s, well under free tier)

# S3 access log format:
# BucketOwner Bucket [Time] RemoteIP Requester RequestID Operation Key "Request-URI" ...
LOG_RE = re.compile(
    r'^\S+ \S+ \[([^\]]+)\] (\S+) \S+ \S+ \S+ \S+ "([^"]*)"'
)

s3 = boto3.client("s3", region_name="us-west-2")
ssm = boto3.client("ssm", region_name="us-west-2")
ses = boto3.client("ses", region_name=SES_REGION)

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


def load_ip_data():
    """Return dict of ip -> geo info dict from ips.csv."""
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=CSV_KEY)
        reader = csv.reader(io.StringIO(resp["Body"].read().decode("utf-8")))
        data = {}
        for row in reader:
            if row and not row[0].startswith("ip"):
                ip = row[0]
                data[ip] = {
                    "ip": ip,
                    "hostname": row[1] if len(row) > 1 else "—",
                    "city": row[2] if len(row) > 2 else "—",
                    "region": row[3] if len(row) > 3 else "—",
                    "country": row[4] if len(row) > 4 else "—",
                    "postal": row[5] if len(row) > 5 else "—",
                    "timezone": row[6] if len(row) > 6 else "—",
                }
        return data
    except s3.exceptions.NoSuchKey:
        return {}


def list_log_keys():
    """Yield all object keys under LOG_PREFIX."""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=LOG_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key != LOG_PREFIX:
                yield key


def parse_s3_timestamp(raw):
    """Convert S3 log timestamp (06/Feb/2019:00:00:38 +0000) to readable UTC string."""
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return raw


def extract_entries_from_log(key):
    """Return list of (ip, timestamp, uri) tuples from a single log file."""
    entries = []
    resp = s3.get_object(Bucket=BUCKET, Key=key)
    for line in resp["Body"].iter_lines():
        decoded = line.decode("utf-8", errors="replace")
        m = LOG_RE.match(decoded)
        if not m:
            continue
        raw_ts, ip, request = m.group(1), m.group(2), m.group(3)
        if ip == "-":
            continue
        # Request is "METHOD /path HTTP/1.1" — extract the path
        parts = request.split()
        uri = parts[1] if len(parts) >= 2 else request
        entries.append((ip, parse_s3_timestamp(raw_ts), uri))
    return entries


def lookup_ip(ip, token):
    """Call ipinfo.io and return a dict of fields, or None on failure."""
    url = f"https://ipinfo.io/{ip}?token={token}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
        return {
            "ip": data.get("ip", ip),
            "hostname": data.get("hostname", "—") or "—",
            "city": data.get("city", "—") or "—",
            "region": data.get("region", "—") or "—",
            "country": data.get("country", "—") or "—",
            "postal": data.get("postal", "—") or "—",
            "timezone": data.get("timezone", "—") or "—",
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


def build_email_html(report_rows, total_new_ips, new_log_files, run_time):
    rows_html = ""
    for row in report_rows:
        rows_html += (
            "<tr>"
            f"<td>{row['timestamp']}</td>"
            f"<td>{row['ip']}</td>"
            f"<td>{row['hostname']}</td>"
            f"<td>{row['city']}</td>"
            f"<td>{row['region']}</td>"
            f"<td>{row['country']}</td>"
            f"<td style='word-break:break-all'>{row['uri']}</td>"
            "</tr>\n"
        )

    return f"""<html><body style="font-family:sans-serif;font-size:14px;color:#222">
<h2 style="margin-bottom:4px">IP Logger Report</h2>
<p style="color:#666;margin-top:0">
  {run_time} &mdash; {new_log_files} log file(s) processed,
  {total_new_ips} new IP(s), {len(report_rows)} request(s)
</p>
<table border="1" cellpadding="6" cellspacing="0"
       style="border-collapse:collapse;font-size:13px;width:100%">
  <tr style="background:#f0f0f0;text-align:left">
    <th>Timestamp</th>
    <th>IP</th>
    <th>Hostname</th>
    <th>City</th>
    <th>Region</th>
    <th>Country</th>
    <th>URI</th>
  </tr>
{rows_html}</table>
</body></html>"""


def send_email_report(report_rows, total_new_ips, new_log_files):
    if not report_rows:
        print("No new log entries — skipping email report.")
        return
    if not REPORT_EMAIL_TO or not REPORT_EMAIL_FROM:
        print("REPORT_EMAIL_TO/FROM not set — skipping email report.")
        return
    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subject = f"IP Logger — {run_time} — {len(report_rows)} request(s)"
    html = build_email_html(report_rows, total_new_ips, new_log_files, run_time)
    try:
        ses.send_email(
            Source=REPORT_EMAIL_FROM,
            Destination={"ToAddresses": [REPORT_EMAIL_TO]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html}},
            },
        )
        print(f"Report emailed to {REPORT_EMAIL_TO}")
    except Exception as e:
        print(f"Failed to send email report: {e}")


def lambda_handler(event, context):
    token = get_ipinfo_token()
    processed = load_state()
    ip_data = load_ip_data()

    # Stop processing new files when this many ms remain — enough time to write
    # partial results and exit cleanly before Lambda kills the process.
    TIME_BUFFER_MS = 30_000

    total_new_ips = 0
    new_log_files = 0
    report_rows = []

    for key in list_log_keys():
        if key in processed:
            continue

        if context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
            print("Approaching timeout — will resume on next invocation.")
            break

        print(f"Processing {key}")
        entries = extract_entries_from_log(key)

        new_ips = sorted({ip for ip, _, _ in entries} - set(ip_data))

        records = []
        interrupted = False
        for ip in new_ips:
            if context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
                print(f"Timeout mid-file {key} — partial results saved, file will be reprocessed.")
                interrupted = True
                break
            info = lookup_ip(ip, token)
            if info:
                records.append(info)
                ip_data[ip] = info
            time.sleep(IPINFO_RATE_LIMIT_DELAY)

        if records:
            append_records_to_csv(records)
            total_new_ips += len(records)

        # Build report rows for all entries in this file (geo info may be partial
        # if interrupted mid-lookup, but include what we have)
        for ip, timestamp, uri in entries:
            geo = ip_data.get(ip, {})
            report_rows.append({
                "timestamp": timestamp,
                "ip": ip,
                "hostname": geo.get("hostname", "—"),
                "city": geo.get("city", "—"),
                "region": geo.get("region", "—"),
                "country": geo.get("country", "—"),
                "uri": uri,
            })

        if interrupted:
            break

        processed.add(key)
        save_state(processed)
        new_log_files += 1

    send_email_report(report_rows, total_new_ips, new_log_files)
    print(f"Run complete: {total_new_ips} new IPs, {new_log_files} log files processed")
    return {"new_ips": total_new_ips, "new_log_files": new_log_files}
