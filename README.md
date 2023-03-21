# AWS Simulate Permissions Checker
AWS Permissions Checker is a Python script that **retrieves a user's permissions in AWS using the `simulate_principal_policy` method**. This tool allows users to quickly and easily identify all their permissions by asking if they have all of them. Permissions are asked in batched of 100 permissions each time.

Moreover, this tool asks if the user **has permissions over the resource "*"**. The tool could be modify to be able to **specify specific resources** to check for.

**NOTE: Permissions from inline policies cannot be discovered using this technique.**

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
python3 bf-aws-perms-simulate.py -h
usage: bf-aws-perms-simulate.py [-h] --profile PROFILE [--arn ARN]

Asks AWS permissions for a user using simulatePrincipalPolicy

optional arguments:
  -h, --help         show this help message and exit
  --profile PROFILE  AWS profile name to use
  --arn ARN          User/Role ARN to check permissions for (by defaults uses
                     current user)

# Replace <AWS_PROFILE> with the name of the AWS profile you want to use. If you don't provide a <USER_ARN>, the script will use the ARN of the profile.
python3 aws_permissions_checker.py --profile <AWS_PROFILE> [--arn <USER_ARN>]
```
