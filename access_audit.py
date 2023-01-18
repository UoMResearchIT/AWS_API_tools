import boto3
import botocore.client
from typing import Type


def print_iam_report(account_details: dict[str: list]):
    # Unpack policies from list into dict
    account_details["Policies"] = {policy["PolicyName"]: policy for policy in account_details["Policies"]}

    with open("iam.txt", 'w') as output_file:
        policy_list = []
        output_file.write("Users, assigned groups and attached managed policies.\n\n")
        for user in account_details["UserDetailList"]:
            attached_managed_policies = [policy["PolicyName"] for policy in user["AttachedManagedPolicies"]]
            policy_list.extend(attached_managed_policies)
            output_file.write(f"{user['UserName']} - {', '.join(user['GroupList'])} - {', '.join(attached_managed_policies)}\n")
        output_file.write("\nGroups and attached policies\n\n")
        for group in account_details["GroupDetailList"]:
            group_policy_names = [policy['PolicyName'] for policy in group['AttachedManagedPolicies']]
            policy_list.extend(group_policy_names)
            output_file.write(f"{group['GroupName']} - {', '.join(group_policy_names)}\n")
        output_file.write("\nPolicy Details\n\n")
        for policy in set(policy_list):
            if policy in account_details["Policies"]:
                output_file.write(f"{policy} - policy document\n")
            else:
                output_file.write(f"{policy} - AWS Managed\n")


def get_account_details(iam_client: Type[botocore.client.BaseClient]) -> dict[str: list]:
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('get_account_authorization_details')
    page_iterator = paginator.paginate(Filter=['User', 'Role', 'Group', 'LocalManagedPolicy'])
    for page in page_iterator:
        for item in details:
            details[item].extend(page[item])
    return details


def audit_access(sso_profile_name: str):
    session = boto3.Session(profile_name=sso_profile_name)
    client = session.client('iam')
    account_details = get_account_details(client)
    print_iam_report(account_details)


if __name__ == "__main__":
    audit_access("old-organisation")
