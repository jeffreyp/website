"""
One-time infrastructure setup for the ip-logger Lambda.

Run this locally (with appropriate AWS credentials) to:
  1. Apply the S3 lifecycle policy — raw log files expire after 90 days.
  2. Print the Lambda ARN so you can wire up the S3 event notification.

Usage:
  python setup_infra.py [--lambda-arn <arn>]

If --lambda-arn is supplied the script also creates the S3 event notification
and adds the required Lambda resource-based policy. If omitted, it prints
instructions for doing that step in the console.
"""

import argparse
import json
import boto3
from botocore.exceptions import ClientError

BUCKET = "logs.jeffreypratt.org"
LOG_PREFIX = "logs/"
LIFECYCLE_RULE_ID = "expire-raw-logs"
EXPIRATION_DAYS = 90
REGION = "us-west-2"

s3 = boto3.client("s3", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)


def apply_lifecycle_policy():
    # Fetch any existing rules so we don't clobber them.
    try:
        existing = s3.get_bucket_lifecycle_configuration(Bucket=BUCKET)
        rules = [r for r in existing["Rules"] if r["ID"] != LIFECYCLE_RULE_ID]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
            rules = []
        else:
            raise

    rules.append({
        "ID": LIFECYCLE_RULE_ID,
        "Status": "Enabled",
        "Filter": {"Prefix": LOG_PREFIX},
        "Expiration": {"Days": EXPIRATION_DAYS},
    })

    s3.put_bucket_lifecycle_configuration(
        Bucket=BUCKET,
        LifecycleConfiguration={"Rules": rules},
    )
    print(f"✓ Lifecycle policy set: {LOG_PREFIX} objects expire after {EXPIRATION_DAYS} days.")


def wire_s3_trigger(lambda_arn):
    function_name = lambda_arn.split(":")[-1]

    # Add resource-based policy so S3 can invoke the Lambda.
    try:
        lam.add_permission(
            FunctionName=function_name,
            StatementId="AllowS3Invoke-ip-logger",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=f"arn:aws:s3:::{BUCKET}",
        )
        print("✓ Lambda resource policy updated — S3 can now invoke the function.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            print("  (Lambda resource policy already has S3 invoke permission — skipping.)")
        else:
            raise

    # Add the S3 bucket notification.
    try:
        existing = s3.get_bucket_notification_configuration(Bucket=BUCKET)
    except ClientError:
        existing = {}

    existing.pop("ResponseMetadata", None)
    configs = existing.get("LambdaFunctionConfigurations", [])

    # Remove any stale config pointing to the same function before re-adding.
    configs = [c for c in configs if c.get("LambdaFunctionArn") != lambda_arn]
    configs.append({
        "LambdaFunctionArn": lambda_arn,
        "Events": ["s3:ObjectCreated:*"],
        "Filter": {
            "Key": {
                "FilterRules": [{"Name": "prefix", "Value": LOG_PREFIX}]
            }
        },
    })

    existing["LambdaFunctionConfigurations"] = configs
    s3.put_bucket_notification_configuration(
        Bucket=BUCKET,
        NotificationConfiguration=existing,
    )
    print(f"✓ S3 event notification created: {BUCKET}/{LOG_PREFIX}* → {lambda_arn}")


def print_console_instructions(lambda_arn=None):
    print()
    print("─" * 60)
    print("Manual step: wire the S3 → Lambda trigger")
    print("─" * 60)
    if lambda_arn:
        return  # already done programmatically
    print("""
1. Open the S3 console → logs.jeffreypratt.org → Properties
   → Event notifications → Create event notification

   Name:        new-log-file
   Prefix:      logs/
   Event type:  s3:ObjectCreated:* (check "All object create events")
   Destination: Lambda function → [select your ip-logger function]

   Save. The console will offer to add the required Lambda
   resource policy — accept it.

2. To find your Lambda ARN:
   Lambda console → ip-logger → copy the ARN from the top-right.
   Then re-run this script with:
     python setup_infra.py --lambda-arn <arn>
   to have it do steps 1-2 automatically next time.
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lambda-arn", help="ARN of the ip-logger Lambda function")
    args = parser.parse_args()

    apply_lifecycle_policy()

    if args.lambda_arn:
        wire_s3_trigger(args.lambda_arn)
    else:
        print_console_instructions()


if __name__ == "__main__":
    main()
