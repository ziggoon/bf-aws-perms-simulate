# AWS Simulate Permissions Checker

AWS Permissions Checker is a Python script that **retrieves a user's permissions in AWS using the `simulate_principal_policy` method**. This tool allows users to quickly and easily identify all their permissions by asking if they have all of them. Permissions are asked in batched of 100 permissions each time.

Moreover, this tool asks if the user **has permissions over the resource "*"**. The tool could be modify to be able to **specify specific resources** to check for.

**NOTE: Permissions from inline policies cannot be discovered using this technique.**

## Requirements

In order to use this tool to check for permissions the user needs to **have the permission `iam:SimulatePrincipalPolicy`**.

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
usage: bf-aws-perms-simulate.py [-h] --profile PROFILE --region REGION [--arn ARN] [--services SERVICES]

Asks AWS permissions for a user using simulatePrincipalPolicy

options:
  -h, --help           show this help message and exit
  --profile PROFILE    AWS profile name to use
  --arn ARN            User/Role ARN to check permissions for (by
                       defaults uses current user)
  --services SERVICES  Comma separated list of services to check
                       permissions for (e.g. s3,ec2,secretsmanager)
  --action ACTION      Specific action to check (e.g. s3:GetObject)
  --resource RESOURCE  Specific resource to check (e.g.
                       arn:aws:secretsmanager:us-
                       east-1:123456789098:secret:secret_name)

# Replace <AWS_PROFILE> with the name of the AWS profile you want to use. If you don't provide a <USER_ARN>, the script will use the ARN of the profile.
python3 aws_permissions_checker.py --profile <AWS_PROFILE> [--arn <USER_ARN>] [--services <SERVICES>] [--action <ACTION>] [--resource <RESOURCE>]
```

- Use `--services` to check permissions only for specific services.
- Use `--action` to check permissions only for the specific action indicated.
- Use `--resource` to check permissions only over the specific resource indicated.