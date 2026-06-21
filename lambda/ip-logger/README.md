# ip-logger

Lambda function that enriches S3 access logs with IP geolocation data.

## What it does

1. **Event-driven path** (S3 ObjectCreated trigger): fires when a new log file lands under `logs/`, looks up unknown IPs via [ipinfo.io](https://ipinfo.io), and appends records to `logs.jeffreypratt.org/ipinfo/ips.csv`. No email.
2. **Scheduled path** (daily cron): lists only the last 24h of log files using `StartAfter` on the lexicographically-ordered key names, counts requests, and emails an HTML summary report (new IPs, top IPs, top URIs).

The CSV columns are: `ip, hostname, city, region, country, postal, timezone, first_seen`

## Infrastructure

- Python 3.12 Lambda, 256 MB memory, 15-minute timeout
- IAM role with:
  - S3 read/write on the logs bucket
  - SSM read for the ipinfo token
  - `ses:SendEmail` on `*` (or scoped to the verified identity ARN)
- ipinfo API token stored in SSM Parameter Store at `/jeffreypratt/ipinfo_token` (SecureString)
- SES: sender address must be verified (or domain verified). If SES is still in sandbox mode, the recipient address must also be verified.
- S3 event notification on `logs.jeffreypratt.org` fires the Lambda on `s3:ObjectCreated:*` for the `logs/` prefix
- EventBridge rule triggers the email report daily at 02:00 UTC
- S3 lifecycle policy: objects under `logs/` expire after 90 days; `ipinfo/ips.csv` is kept indefinitely

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LOG_BUCKET` | `logs.jeffreypratt.org` | S3 bucket containing access logs and CSV |
| `LOG_PREFIX` | `logs/` | S3 prefix for raw access log files |
| `CSV_KEY` | `ipinfo/ips.csv` | S3 key for the IP geo-info CSV |
| `IPINFO_TOKEN_PARAM` | `/jeffreypratt/ipinfo_token` | SSM parameter name for the ipinfo token |
| `REPORT_EMAIL_TO` | *(required)* | Recipient for the daily report |
| `REPORT_EMAIL_FROM` | *(required)* | SES verified sender address |
| `SES_REGION` | `us-west-2` | AWS region where SES is configured |

## Deploying

The function has no external dependencies (boto3 is provided by the Lambda runtime). To deploy:

```bash
zip /tmp/ip-logger.zip lambda_function.py
aws lambda update-function-code --function-name jeffreypratt-ip-logger --zip-file fileb:///tmp/ip-logger.zip --region us-west-2
```

To invoke manually (scheduled/email path):

```bash
aws lambda invoke --function-name jeffreypratt-ip-logger --region us-west-2 /tmp/out.json && cat /tmp/out.json
```

To invoke manually (event-driven path, using an existing log key):

```bash
echo '{"Records":[{"eventSource":"aws:s3","s3":{"bucket":{"name":"logs.jeffreypratt.org"},"object":{"key":"logs/KEYNAME"}}}]}' > /tmp/test-event.json
aws lambda invoke --function-name jeffreypratt-ip-logger --region us-west-2 --payload fileb:///tmp/test-event.json /tmp/out.json && cat /tmp/out.json
```

## Rebuilding infrastructure from scratch

1. Store the ipinfo token in SSM as a SecureString at `/jeffreypratt/ipinfo_token`
2. Create an IAM role (`jeffreypratt-ip-logger-role`) with S3, SSM, and SES permissions
3. Create the Lambda function (`jeffreypratt-ip-logger`) from `lambda_function.py`
4. Add an S3 event notification on `logs.jeffreypratt.org` for `s3:ObjectCreated:*` with prefix `logs/`, targeting the Lambda ARN
5. Add a Lambda resource policy allowing `s3.amazonaws.com` to invoke the function
6. Create an EventBridge rule (`jeffreypratt-ip-logger-schedule`) on `cron(0 2 * * ? *)` targeting the Lambda
7. Apply an S3 lifecycle rule expiring `logs/` objects after 90 days
