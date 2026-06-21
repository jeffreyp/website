"""
Parses S3 access logs from logs.jeffreypratt.org/logs/.

Event-driven path (S3 ObjectCreated trigger): processes the new log file(s),
looks up unknown IPs via ipinfo.io, and appends records to
logs.jeffreypratt.org/ipinfo/ips.csv. No email.

Scheduled path (CloudWatch cron, daily at 7 PM PDT): lists only the last 24h
of log files using StartAfter on the lexicographically-ordered key names,
counts requests, identifies new IPs from ips.csv (first_seen within window),
and emails a summary report.

ips.csv columns: ip, hostname, city, region, country, postal, timezone, first_seen
Old rows without first_seen are read and written correctly; they just won't
appear in the "new IPs" section of reports.
"""

import boto3
import collections
import csv
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

BUCKET = os.environ.get("LOG_BUCKET", "logs.jeffreypratt.org")
LOG_PREFIX = os.environ.get("LOG_PREFIX", "logs/")
CSV_KEY = os.environ.get("CSV_KEY", "ipinfo/ips.csv")
IPINFO_TOKEN_PARAM = os.environ.get("IPINFO_TOKEN_PARAM", "/jeffreypratt/ipinfo_token")
REPORT_EMAIL_TO = os.environ.get("REPORT_EMAIL_TO", "")
REPORT_EMAIL_FROM = os.environ.get("REPORT_EMAIL_FROM", "")
SES_REGION = os.environ.get("SES_REGION", "us-west-2")
IPINFO_RATE_LIMIT_DELAY = 0.05  # seconds between requests (~20 req/s, well under free tier)
TOP_N = 20
REPORT_WINDOW_HOURS = 24

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


def load_ip_data():
    """Return dict of ip -> info dict from ips.csv."""
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=CSV_KEY)
        reader = csv.reader(io.StringIO(resp["Body"].read().decode("utf-8")))
        data = {}
        for row in reader:
            if not row or row[0].startswith("ip"):
                continue
            ip = row[0]
            data[ip] = {
                "ip": ip,
                "hostname": row[1] if len(row) > 1 else "—",
                "city": row[2] if len(row) > 2 else "—",
                "region": row[3] if len(row) > 3 else "—",
                "country": row[4] if len(row) > 4 else "—",
                "postal": row[5] if len(row) > 5 else "—",
                "timezone": row[6] if len(row) > 6 else "—",
                "first_seen": row[7] if len(row) > 7 else None,
            }
        return data
    except s3.exceptions.NoSuchKey:
        return {}


def append_records_to_csv(records, existing=None):
    """Append new rows to the CSV. Reads S3 once if existing content not supplied;
    returns updated content so callers can pass it through on subsequent calls."""
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
        writer.writerow([
            r["ip"], r["hostname"], r["city"], r["region"],
            r["country"], r["postal"], r["timezone"],
            r.get("first_seen", ""),
        ])

    updated = buf.getvalue()
    s3.put_object(
        Bucket=BUCKET,
        Key=CSV_KEY,
        Body=updated.encode("utf-8"),
        ContentType="text/csv",
    )
    return updated


def parse_s3_timestamp(raw):
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
            "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} looking up {ip}")
        return None
    except Exception as e:
        print(f"Error looking up {ip}: {e}")
        return None


def list_keys_since(since_dt):
    """Yield log keys whose names are >= since_dt.
    Log key names are UTC timestamps so lexicographic order == time order."""
    start_after = LOG_PREFIX + since_dt.strftime("%Y-%m-%d-%H-%M-%S")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=LOG_PREFIX, StartAfter=start_after):
        for obj in page.get("Contents", []):
            yield obj["Key"]


def process_files(keys, ip_data, context=None):
    """Process a list of log keys: look up unknown IPs, append to ips.csv,
    accumulate request counts. Returns (ip_counts, uri_counts, total_requests, files_processed)."""
    TIME_BUFFER_MS = 30_000
    ip_counts = collections.Counter()
    uri_counts = collections.Counter()
    total_requests = 0
    csv_content = None
    files_processed = 0
    token = get_ipinfo_token()

    for key in keys:
        if context and context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
            print("Approaching timeout — stopping early.")
            break

        print(f"Processing {key}")
        entries = extract_entries_from_log(key)

        new_ips = sorted({ip for ip, _, _ in entries} - set(ip_data))
        records = []
        for ip in new_ips:
            if context and context.get_remaining_time_in_millis() < TIME_BUFFER_MS:
                print(f"Timeout mid-file {key} — partial IP lookups saved.")
                break
            info = lookup_ip(ip, token)
            if info:
                records.append(info)
                ip_data[ip] = info
            time.sleep(IPINFO_RATE_LIMIT_DELAY)

        if records:
            csv_content = append_records_to_csv(records, csv_content)

        for ip, _ts, uri in entries:
            ip_counts[ip] += 1
            uri_counts[uri] += 1
        total_requests += len(entries)
        files_processed += 1

    return ip_counts, uri_counts, total_requests, files_processed


TABLE_STYLE = 'border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:13px"'
TH_STYLE = 'style="background:#f0f0f0;text-align:left"'


def _table(headers, rows):
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join(
        "<tr>" + "".join(f"<td style='word-break:break-all'>{c}</td>" for c in row) + "</tr>\n"
        for row in rows
    )
    return f'<table {TABLE_STYLE}><tr {TH_STYLE}>{ths}</tr>\n{trs}</table>'


def build_email_html(new_ip_records, top_ips, top_uris, total_requests, file_count, run_time):
    total_new_ips = len(new_ip_records)

    if new_ip_records:
        new_ip_table = _table(
            ["IP", "Hostname", "City", "Region", "Country", "First Seen"],
            [
                (r["ip"], r["hostname"], r["city"], r["region"], r["country"],
                 r.get("first_seen") or "—")
                for r in new_ip_records
            ],
        )
        new_ip_section = f"<h3 style='margin-top:24px'>New IPs &mdash; {total_new_ips}</h3>{new_ip_table}"
    else:
        new_ip_section = f"<p style='color:#666'>No new IPs in the last {REPORT_WINDOW_HOURS}h.</p>"

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
  {run_time} &mdash; {file_count} log file(s) in the last {REPORT_WINDOW_HOURS}h,
  {total_new_ips} new IP(s), {total_requests} request(s)
</p>
{new_ip_section}
<h3 style="margin-top:24px">Top {TOP_N} IPs by Request Count (last {REPORT_WINDOW_HOURS}h)</h3>
{top_ip_table}
<h3 style="margin-top:24px">Top {TOP_N} URIs by Request Count (last {REPORT_WINDOW_HOURS}h)</h3>
{top_uri_table}
</body></html>"""


def send_email_report(new_ip_records, ip_counts, uri_counts, total_requests, file_count, ip_data):
    if total_requests == 0:
        print("No log entries in window — skipping email report.")
        return
    if not REPORT_EMAIL_TO or not REPORT_EMAIL_FROM:
        print("REPORT_EMAIL_TO/FROM not set — skipping email report.")
        return

    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subject = f"IP Logger — {run_time} — {total_requests} request(s), {len(new_ip_records)} new IP(s)"

    top_ips = [
        (ip, ip_data.get(ip, {}).get("city", "—"), ip_data.get(ip, {}).get("country", "—"), count)
        for ip, count in ip_counts.most_common(TOP_N)
    ]
    top_uris = uri_counts.most_common(TOP_N)

    html = build_email_html(new_ip_records, top_ips, top_uris, total_requests, file_count, run_time)
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
    # --- S3 event-driven path ---
    # Invoked when a new log file lands. Process just those file(s); no email.
    s3_records = [r for r in event.get("Records", []) if r.get("eventSource") == "aws:s3"]
    if s3_records:
        ip_data = load_ip_data()
        keys = [urllib.parse.unquote_plus(r["s3"]["object"]["key"]) for r in s3_records]
        _, _, total_requests, files_processed = process_files(keys, ip_data, context)
        print(f"S3 event complete: {files_processed} file(s), {total_requests} request(s)")
        return {"files_processed": files_processed, "total_requests": total_requests}

    # --- Scheduled path ---
    # Invoked by the daily cron. List only the last REPORT_WINDOW_HOURS of files
    # (StartAfter makes this O(new files) not O(all files ever), then send email.
    ip_data = load_ip_data()
    since = datetime.now(timezone.utc) - timedelta(hours=REPORT_WINDOW_HOURS)

    keys = list(list_keys_since(since))
    ip_counts, uri_counts, total_requests, file_count = process_files(keys, ip_data, context)

    # "New IPs" for the email = any IP whose first_seen falls within the report window.
    # This captures IPs added by earlier event invocations today, not just this run.
    since_str = since.strftime("%Y-%m-%d %H:%M:%S UTC")
    new_ip_records = [
        info for info in ip_data.values()
        if info.get("first_seen") and info["first_seen"] >= since_str
    ]

    send_email_report(new_ip_records, ip_counts, uri_counts, total_requests, file_count, ip_data)
    print(f"Scheduled run complete: {file_count} file(s), {len(new_ip_records)} new IP(s)")
    return {"new_ips": len(new_ip_records), "files_processed": file_count}
