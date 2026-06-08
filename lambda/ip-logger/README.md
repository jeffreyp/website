# ip-logger

Lambda function that enriches S3 access logs with IP geolocation data.

## What it does

1. Reads S3 access logs from `logs.jeffreypratt.org/logs/`
2. Extracts every request (IP, timestamp, URI) from each new log file
3. Looks up geo info for new IPs via [ipinfo.io](https://ipinfo.io)
4. Appends new IP records to `logs.jeffreypratt.org/ipinfo/ips.csv`
5. Tracks processed files in `ipinfo/processed_logs.json` so nothing is read twice
6. Emails an HTML report of all requests seen in this run via SES

The CSV columns are: `ip, hostname, city, region, country, postal, timezone`

The email report columns are: `timestamp, ip, hostname, city, region, country, uri`

## Infrastructure

- Python 3.12 Lambda, 256 MB memory, 15-minute timeout
- IAM role with:
  - S3 read/write on the logs bucket
  - SSM read for the ipinfo token
  - `ses:SendEmail` on `*` (or scoped to the verified identity ARN)
- ipinfo API token stored in SSM Parameter Store at `/jeffreypratt/ipinfo_token` (SecureString)
- SES: sender address must be verified (or domain verified). If SES is still in sandbox mode, the recipient address must also be verified.
- EventBridge rule triggers daily at 02:00 UTC

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LOG_BUCKET` | `logs.jeffreypratt.org` | S3 bucket containing access logs and CSV |
| `LOG_PREFIX` | `logs/` | S3 prefix for raw access log files |
| `CSV_KEY` | `ipinfo/ips.csv` | S3 key for the IP geo-info CSV |
| `STATE_KEY` | `ipinfo/processed_logs.json` | S3 key for the processed-files state |
| `IPINFO_TOKEN_PARAM` | `/jeffreypratt/ipinfo_token` | SSM parameter name for the ipinfo token |
| `REPORT_EMAIL_TO` | *(required)* | Recipient for the run report |
| `REPORT_EMAIL_FROM` | *(required)* | SES verified sender address |
| `SES_REGION` | `us-west-2` | AWS region where SES is configured |

## Backlog handling

On first run, the function processes one log file at a time and saves state after each. If it approaches the 15-minute timeout, it stops cleanly and resumes on the next daily invocation. A multi-year backlog drains incrementally over several days.

## Deploying

The deploy script is not committed (it contains the ipinfo API token). To redeploy from scratch, you'll need to recreate a script that:

1. Stores the ipinfo token in SSM as a SecureString at `/jeffreypratt/ipinfo_token`
2. Creates an IAM role (`jeffreypratt-ip-logger-role`) with S3 and SSM permissions
3. Creates the Lambda function (`jeffreypratt-ip-logger`) from `lambda_function.py`
4. Creates an EventBridge rule (`jeffreypratt-ip-logger-schedule`) on `cron(0 2 * * ? *)`

To invoke manually:

```bash
aws lambda invoke --function-name jeffreypratt-ip-logger --region us-west-2 /tmp/out.json && cat /tmp/out.json
```
