import boto3
import botocore.client
import botocore.exceptions
from typing import Type

import tqdm as tqdm

from config import get_profiles_in_sso

OUTPUT_NAME = "iam.txt"


class NoAccessException(Exception):
    pass


def print_iam_report(account_details: dict[str: dict] | None, account_name: str):
    # Unpack policies from list into dict

    with open(OUTPUT_NAME, 'a') as output_file:
        policy_list = []
        output_file.write(f"IAM report for account {account_name}.\n\n")
        output_file.write("Users and policies.\n\n")

        if account_details is None:
            output_file.write("Access denied when trying to enumerate roles. Check account permissions")
        else:
            for username, user_details in account_details["Users"].items():
                attached_policies, group_policies = get_users_policies(user_details, account_details["Groups"])
                attached_policies = [f"{policy} (a)" for policy in attached_policies]
                group_policies = [f"{policy} (g)" for policy in group_policies]
                output_file.write(f"{username} - {', '.join(group_policies)}, {', '.join(attached_policies)}\n")
            output_file.write("\nGroups and attached policies\n\n")
            for group_name, group_details in account_details["Groups"].items():
                group_policy_names = [policy['PolicyName'] for policy in group_details['AttachedManagedPolicies']]
                policy_list.extend(group_policy_names)
                output_file.write(f"{group_name} - {', '.join(group_policy_names)}\n")
            output_file.write("\nPolicy Details\n\n")
            for policy in set(policy_list):
                if policy in account_details["Policies"]:
                    output_file.write(f"{policy} - policy document\n")
                else:
                    output_file.write(f"{policy} - AWS Managed\n")
        output_file.write("\n\n")


def get_users_policies(user_details: dict, group_details: dict) -> tuple[list[str], list[str]]:
    """Return the policies directly attached to a user and the policies attached to groups the user is in."""
    attached_managed_policies = [policy["PolicyName"] for policy in user_details["AttachedManagedPolicies"]]
    user_groups = user_details["GroupList"]
    group_policies = []
    for group_name in user_groups:
        group_policies.extend([policy['PolicyName'] for policy in group_details[group_name]['AttachedManagedPolicies']])
    return attached_managed_policies, group_policies


def get_account_details(iam_client: Type[botocore.client.BaseClient]) -> dict[str: dict]:
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('get_account_authorization_details')
    page_iterator = paginator.paginate(Filter=['User', 'Role', 'Group', 'LocalManagedPolicy'])
    try:
        for page in page_iterator:
            for item in details:
                details[item].extend(page[item])
    except botocore.exceptions.ClientError:
        raise NoAccessException
    # Unpack lists of items into dicts
    details["Users"] = {user["UserName"]: user for user in details.pop("UserDetailList")}
    details["Groups"] = {group["GroupName"]: group for group in details.pop("GroupDetailList")}
    details["Roles"] = {role["RoleName"]: role for role in details.pop("RoleDetailList")}
    details["Policies"] = {policy["PolicyName"]: policy for policy in details.pop("Policies")}

    return details


def audit_account_access(sso_session: boto3.Session):
    iam_client = sso_session.client('iam')
    try:
        account_details = get_account_details(iam_client)
    except NoAccessException:
        account_details = None

    print_iam_report(account_details, sso_session.profile_name)


def audit_all_account_access(sso_profile_name: str):
    """Loop through all the accounts in a single SSO profile, getting IAM information for each one."""
    profile_names = get_profiles_in_sso(sso_profile_name)
    with open(OUTPUT_NAME, 'w') as output_file:
        output_file.write(f"Report on user access for accounts with the same SSO profile as the "
                          f"'{sso_profile_name}' profile.\n")
    for account_name in tqdm.tqdm(profile_names):
        session = boto3.Session(profile_name=account_name)
        audit_account_access(session)


if __name__ == "__main__":
    audit_all_account_access("old-organisation")
