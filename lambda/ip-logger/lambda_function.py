"""
Parses S3 access logs from logs.jeffreypratt.org/logs/,
looks up new IPs via ipinfo.io, appends records to
logs.jeffreypratt.org/ipinfo/ips.csv, and emails a summary
report (new IPs, top IPs, top URIs) for the run.

Tracks processed log files in logs.jeffreypratt.org/ipinfo/processed_logs.json
so each file is only read once.
"""

import boto3
import collections
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
SES_REGION = os.environ.get("SES_REGION", "us-west-2")
IPINFO_RATE_LIMIT_DELAY = 0.05  # seconds between requests (~20 req/s, well under free tier)
TOP_N = 20  # rows in top-IPs and top-URIs email tables

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


def append_records_to_csv(records, existing=None):
    """Append new rows to the CSV. Reads S3 once if existing content not supplied;
    returns the updated content so callers can pass it on subsequent calls."""
    if existing is None:
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

    updated = buf.getvalue()
    s3.put_object(
        Bucket=BUCKET,
        Key=CSV_KEY,
        Body=updated.encode("utf-8"),
        ContentType="text/csv",
    )
    return updated


TABLE_STYLE = 'border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:13px"'
TH_STYLE = 'style="background:#f0f0f0;text-align:left"'


def _table(headers, rows):
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join(
        "<tr>" + "".join(f"<td style='word-break:break-all'>{c}</td>" for c in row) + "</tr>\n"
        for row in rows
    )
    return f'<table {TABLE_STYLE}><tr {TH_STYLE}>{ths}</tr>\n{trs}</table>'


def build_email_html(new_ip_records, top_ips, top_uris, total_requests, new_log_files, run_time):
    total_new_ips = len(new_ip_records)

    if new_ip_records:
        new_ip_table = _table(
            ["IP", "Hostname", "City", "Region", "Country"],
            [(r["ip"], r["hostname"], r["city"], r["region"], r["country"]) for r in new_ip_records],
        )
        new_ip_section = f"<h3 style='margin-top:24px'>New IPs &mdash; {total_new_ips}</h3>{new_ip_table}"
    else:
        new_ip_section = "<p style='color:#666'>No new IPs this run.</p>"

    top_ip_table = _table(
        ["IP", "City", "Country", "Requests"],
        [(ip, city, country, count) for ip, city, country, count in top_ips],
    )

    top_uri_table = _table(
        ["URI", "Requests"],
        [(uri, count) for uri, count in top_uris],
    )

    return f"""<html><body style="font-family:sans-serif;font-size:14px;color:#222">
<h2 style="margin-bottom:4px">IP Logger Report</h2>
<p style="color:#666;margin-top:0">
  {run_time} &mdash; {new_log_files} log file(s) processed,
  {total_new_ips} new IP(s), {total_requests} request(s)
</p>
{new_ip_section}
<h3 style="margin-top:24px">Top {TOP_N} IPs by Request Count</h3>
{top_ip_table}
<h3 style="margin-top:24px">Top {TOP_N} URIs by Request Count</h3>
{top_uri_table}
</body></html>"""


def send_email_report(new_ip_records, ip_counts, uri_counts, total_requests, new_log_files, ip_data):
    if total_requests == 0:
        print("No new log entries — skipping email report.")
        return
    if not REPORT_EMAIL_TO or not REPORT_EMAIL_FROM:
        print("REPORT_EMAIL_TO/FROM not set — skipping email report.")
        return

    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subject = (
        f"IP Logger — {run_time} — {total_requests} request(s), {len(new_ip_records)} new IP(s)"
    )

    top_ips = [
        (ip, ip_data.get(ip, {}).get("city", "—"), ip_data.get(ip, {}).get("country", "—"), count)
        for ip, count in ip_counts.most_common(TOP_N)
    ]
    top_uris = uri_counts.most_common(TOP_N)

    html = build_email_html(new_ip_records, top_ips, top_uris, total_requests, new_log_files, run_time)
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

    new_log_files = 0
    new_ip_records = []   # geo dicts for IPs seen for the first time this run
    ip_counts = collections.Counter()
    uri_counts = collections.Counter()
    total_requests = 0
    csv_content = None    # loaded once on first CSV write, threaded through subsequent calls

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
                new_ip_records.append(info)
            time.sleep(IPINFO_RATE_LIMIT_DELAY)

        if records:
            # Pass csv_content through so S3 is read at most once across the whole run.
            csv_content = append_records_to_csv(records, csv_content)

        for ip, _ts, uri in entries:
            ip_counts[ip] += 1
            uri_counts[uri] += 1
        total_requests += len(entries)

        if interrupted:
            break

        processed.add(key)
        save_state(processed)
        new_log_files += 1

    send_email_report(new_ip_records, ip_counts, uri_counts, total_requests, new_log_files, ip_data)
    total_new_ips = len(new_ip_records)
    print(f"Run complete: {total_new_ips} new IPs, {new_log_files} log files processed")
    return {"new_ips": total_new_ips, "new_log_files": new_log_files}
