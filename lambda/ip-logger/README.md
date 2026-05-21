# ip-logger

Lambda function that enriches S3 access logs with IP geolocation data.

## What it does

1. Reads S3 access logs from `logs.jeffreypratt.org/logs/`
2. Extracts unique visitor IPs from each log file
3. Looks each new IP up via [ipinfo.io](https://ipinfo.io)
4. Appends results to `logs.jeffreypratt.org/ipinfo/ips.csv`
5. Tracks processed files in `ipinfo/processed_logs.json` so nothing is read twice

The CSV columns are: `ip, hostname, city, region, country, postal, timezone`

## Infrastructure

- Python 3.12 Lambda, 256 MB memory, 15-minute timeout
- IAM role with S3 read/write on the logs bucket and SSM read for the ipinfo token
- ipinfo API token stored in SSM Parameter Store at `/jeffreypratt/ipinfo_token` (SecureString)
- EventBridge rule triggers daily at 02:00 UTC

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
