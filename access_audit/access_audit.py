from typing import Type

import boto3
import botocore.client
import botocore.exceptions
import tqdm as tqdm
import jinja2
import dill

from config import get_profiles_in_sso

OUTPUT_NAME = "iam.txt"


class NoAccessException(Exception):
    pass


class Policy:
    def __init__(self, name: str):
        self.name: str = name


class User:
    def __init__(self, username: str):
        self.username: str = username
        self.groups: list[str] = []
        self.attached_policies: list[Policy] = []
        self.group_policies: list[Policy] = []


class Account:
    def __init__(self, name: str):
        self.name: str = name
        self.users: list[User] = []


POLICIES: dict[str: dict[str: Policy]] = {}


def generate_report(sso_profile_name: str, account_details: dict):

    accounts = []

    for account_name in account_details:
        new_account = Account(account_name)
        for username, user_details in account_details[account_name]["Users"].items():
            new_user = User(username)
            new_user.groups = user_details["GroupList"]
            attached_policy_names = [policy["PolicyName"] for policy in user_details["AttachedManagedPolicies"]]
            new_user.attached_policies = [get_policy(policy_name, account_name) for policy_name in attached_policy_names]
            group_policy_names = get_group_policies(user_details, account_details[account_name]["Groups"])
            new_user.group_policies = [get_policy(policy_name, account_name) for policy_name in group_policy_names]
            new_account.users.append(new_user)
        accounts.append(new_account)

    env = jinja2.Environment(loader=jinja2.PackageLoader("access_audit"), autoescape=jinja2.select_autoescape(),
                             undefined=jinja2.StrictUndefined)
    template = env.get_template("report_template.html")
    report = template.render(sso_profile_name=sso_profile_name, accounts=accounts, policies=POLICIES)

    with open("iam_report.html", 'w') as output_file:
        output_file.write(report)

        # if account_details is None:
        #     output_file.write("Access denied when trying to enumerate roles. Check account permissions")
        # else:
        #     for username, user_details in account_details["Users"].items():
        #         attached_policies, group_policies = get_users_policies(user_details, account_details["Groups"])
        #         attached_policies = [f"{policy} (a)" for policy in attached_policies]
        #         group_policies = [f"{policy} (g)" for policy in group_policies]
        #         output_file.write(f"{username} - {', '.join(group_policies)}, {', '.join(attached_policies)}\n")
        #     output_file.write("\nGroups and attached policies\n\n")
        #     for group_name, group_details in account_details["Groups"].items():
        #         group_policy_names = [policy['PolicyName'] for policy in group_details['AttachedManagedPolicies']]
        #         policy_list.extend(group_policy_names)
        #         output_file.write(f"{group_name} - {', '.join(group_policy_names)}\n")
        #     output_file.write("\nPolicy Details\n\n")
        #     for policy in set(policy_list):
        #         if policy in account_details["Policies"]:
        #             output_file.write(f"{policy} - policy document\n")
        #         else:
        #             output_file.write(f"{policy} - AWS Managed\n")
        # output_file.write("\n\n")


def get_policy(policy_name: str, account_name: dict[str: Policy]) -> Policy:
    """Get a policy from the global dictionary. If a policy is not present, create it and return it."""
    if account_name not in POLICIES:
        POLICIES[account_name] = {}
    if policy_name not in POLICIES[account_name]:
        POLICIES[account_name][policy_name] = Policy(policy_name)
    return POLICIES[account_name][policy_name]


def get_group_policies(user_details: dict, group_details: dict) -> list[str]:
    """Return the policies directly attached to a user and the policies attached to groups the user is in."""
    group_policies = []
    for group_name in user_details["GroupList"]:
        group_policies.extend([policy['PolicyName'] for policy in group_details[group_name]['AttachedManagedPolicies']])
    return group_policies


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
    return account_details


def save_account_details(account_details: dict):
    with open("iam.txt", 'wb') as output_file:
        dill.dump(account_details, output_file)


def load_account_details():
    with open("iam.txt", 'rb') as input_file:
        return dill.load(input_file)


def audit_all_account_access(sso_profile_name: str):
    """Loop through all the accounts in a single SSO profile, getting IAM information for each one."""
    # profile_names = get_profiles_in_sso(sso_profile_name)
    # account_details = {}
    # for account_name in tqdm.tqdm(profile_names[0:3]):
    #     session = boto3.Session(profile_name=account_name)
    #     account_details[account_name] = audit_account_access(session)
    # save_account_details(account_details)
    account_details = load_account_details()
    generate_report(sso_profile_name, account_details)


if __name__ == "__main__":
    audit_all_account_access("old-organisation")
