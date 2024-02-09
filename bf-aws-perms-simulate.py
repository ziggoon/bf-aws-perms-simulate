import argparse
import boto3
import json
import requests

from termcolor import colored
from tqdm import tqdm
from typing import Dict, List, Optional


def get_aws_permissions() -> Dict[str, List[str]]:
    """
    Download all the AWS permissions per service from the AWS Policy Generator.
    
    Returns:
        permissions (Dict[str, List[str]]): A dictionary containing service names as keys and action lists as values.
    """
    url = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
    response = requests.get(url)

    if response.status_code != 200:
        print(colored("Error: Unable to fetch AWS policies.", "red"))
        return {}

    resp_text = response.text.replace("app.PolicyEditorConfig=", "")
    policies = json.loads(resp_text)
    permissions = {}

    for service in policies["serviceMap"]:
        service_name = policies["serviceMap"][service]["StringPrefix"]
        actions = [action for action in policies["serviceMap"][service]["Actions"]]
        permissions[service_name] = actions

    return permissions


def check_principal_permissions(
    permissions: Dict[str, List[str]],
    iam_client: boto3.client,
    principal_arn: str,
    services: Optional[List[str]] = None,
    actions: Optional[List[str]] = None,
    resources: Optional[List[str]] = None,
    batch_size: int = 100,
) -> List[str]:
    """
    Check all the permissions of a principal using simulate_principal_policy.
    
    Args:
        permissions (Dict[str, List[str]]): A dictionary containing service names as keys and action lists as values.
        iam_client (boto3.client): IAM client object from boto3.
        principal_arn (str): The ARN of the principal to check permissions for.
        batch_size (int, optional): The size of the action batches to simulate. Defaults to 50.

    Returns:
        principal_permissions (List[str]): A list of allowed permissions for the principal.
    """

    principal_permissions = []

    if actions and resources:
        response = iam_client.simulate_principal_policy(PolicySourceArn=principal_arn, ActionNames=actions, ResourceArns=resources)
        for result in response["EvaluationResults"]:
            allowed = result["EvalDecision"] == "allowed"
            action = result["EvalActionName"]

            if allowed:
                principal_permissions.append(action)

        return principal_permissions

    action_batches = [f"{service}:{action}" for service, actions in permissions.items() for action in actions if not services or service in services]

    print(colored(f"Checking {len(action_batches)} permissions for {principal_arn}...", "cyan"))

    for i in tqdm(range(0, len(action_batches), batch_size)):
        perms = action_batches[i:i + batch_size]
        response = iam_client.simulate_principal_policy(PolicySourceArn=principal_arn, ActionNames=perms)

        for result in response["EvaluationResults"]:
            allowed = result["EvalDecision"] == "allowed"
            action = result["EvalActionName"]

            if allowed:
                principal_permissions.append(action)

    return principal_permissions


def main(aws_profile: str, principal_arn: Optional[str] = "", services: Optional[str] = "") -> None:
    """
    Main function to check principal permissions.

    Args:
        aws_profile (str): AWS profile name to use.
        principal_arn (Optional[str], optional): principal ARN to check permissions for. Defaults to an empty string.
    """

    if services:
        services = services.split(",")
        services = [service.strip().lower() for service in services]
    
    boto_session = boto3.Session(profile_name=aws_profile)
    iam_client = boto_session.client("iam")

    if not principal_arn:
        sts_client = boto_session.client("sts")
        principal = sts_client.get_caller_identity()
        principal_arn = principal["Arn"]

    if not principal_arn:
        print(colored("Error: Unable to get principal ARN, please specify it.", "red"))
        return

    aws_permissions = get_aws_permissions()

    if not aws_permissions:
        print(colored("Error: Unable to get AWS permissions.", "red"))
        return
    
    principal_permissions = check_principal_permissions(aws_permissions, iam_client, principal_arn, services)
    principal_permissions = sorted(principal_permissions)

    # Print principal permissions nicely
    print(colored("principal Permissions:", "green"))
    for permission in principal_permissions:
        print(colored(f"  - {permission}", "yellow"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asks AWS permissions for a principal using simulatePrincipalPolicy")
    parser.add_argument("--profile", type=str, required=True, help="AWS profile name to use")
    parser.add_argument("--arn", type=str, required=False, help="principal (user, role, group) ARN to check permissions for (by default uses the one of the profile)")
    parser.add_argument("--services", type=str, required=False, help="Comma separated list of services to check permissions for (e.g. s3,ec2,secretsmanager)")
    parser.add_argument("--action", type=str, required=False, help="Specific action to check (e.g. s3:GetObject)")
    parser.add_argument("--resource", type=str, required=False, help="Specific resource to check (e.g. arn:aws:secretsmanager:us-east-1:123456789098:secret:secret_name)")

    args = parser.parse_args()
    main(aws_profile=args.profile,  principal_arn=args.arn, services=args.services)

