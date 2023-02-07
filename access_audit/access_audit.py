import pathlib
from typing import Type, Optional
import json

import boto3
import botocore.client
import botocore.exceptions
import tqdm as tqdm
import jinja2
import dill


from config import get_profiles_in_sso

OUTPUT_NAME = "iam.txt"
POLICY_CACHE: dict[str: str] = {}


class NoAccessException(Exception):
    pass


class Policy:
    def __init__(self, arn: str):
        self.name: str = ""
        self.text: str = ""
        self.arn: str = arn
        self.version: str = ""
        self.description: str = ""
        if self.arn.startswith("arn:aws:iam::aws:policy"):
            self.aws_managed = True
        else:
            self.aws_managed = False

    def __repr__(self):
        return f"{self.arn}"

    def get_policy_details(self, iam_client: Type[botocore.client.BaseClient]):
        """Details of AWS managed policies are not downloaded with the get_account_authorization_details API request,
         since they are quite large. We can instead download the policies once and cache the information."""
        global POLICY_CACHE

        cache_path = pathlib.Path("policy_cache.bin")

        if not POLICY_CACHE:
            if cache_path.exists():
                with open(cache_path, 'rb') as input_file:
                    POLICY_CACHE = dill.load(input_file)

        if self.arn not in POLICY_CACHE:
            policy = iam_client.get_policy(PolicyArn=self.arn)["Policy"]
            self.name = policy["PolicyName"]
            self.version = policy["DefaultVersionId"]
            if "Description" in policy:
                self.description = policy["Description"]
            policy_text = iam_client.get_policy_version(PolicyArn=self.arn, VersionId=self.version)
            self.text = json.dumps(policy_text["PolicyVersion"]["Document"], indent=2).replace("\n", "<br>")
            POLICY_CACHE[self.arn] = self

            with open(cache_path, 'wb') as output_file:
                dill.dump(POLICY_CACHE, output_file)

        else:
            self.name = POLICY_CACHE[self.arn].name
            self.version = POLICY_CACHE[self.arn].version
            self.description = POLICY_CACHE[self.arn].description
            self.text = POLICY_CACHE[self.arn].text


class User:
    def __init__(self, username: str, account_details: dict):
        self.username: str = username

        user_details = account_details["Users"][self.username]
        self.groups = user_details["GroupList"]
        self.attached_policy_arns = [policy["PolicyArn"] for policy in user_details["AttachedManagedPolicies"]]
        self.group_policy_arns = get_group_policy_arns(user_details, account_details["Groups"])
        self.attached_polices: list[Policy] = []
        self.group_policies: list[Policy] = []


class Account:
    def __init__(self, name: str, account_details: dict):
        self.name: str = name
        self.users: list[User] = []
        self.policies = {}

        for username, user_details in account_details["Users"].items():
            self.users.append(User(username, account_details))

        for user in self.users:
            user.attached_policies = [get_policy(policy_name, self.policies) for
                                      policy_name in user.attached_policy_arns]
            user.group_policies = [get_policy(policy_arn, self.policies) for
                                   policy_arn in user.group_policy_arns]


def generate_report(sso_profile_name: str, accounts: list[Account]):
    env = jinja2.Environment(loader=jinja2.PackageLoader("access_audit"), autoescape=jinja2.select_autoescape(),
                             undefined=jinja2.StrictUndefined)
    template = env.get_template("report_template.html")
    report = template.render(sso_profile_name=sso_profile_name, accounts=accounts)

    with open("iam_report.html", 'w') as output_file:
        output_file.write(report)


def get_policy(policy_arn: str, account_policies: dict[str: Policy]) -> Policy:
    """Get a policy from the global dictionary. If a policy is not present, create it and return it."""
    if policy_arn not in account_policies:
        account_policies[policy_arn] = Policy(policy_arn)
    return account_policies[policy_arn]


def get_group_policy_arns(user_details: dict, group_details: dict) -> list[str]:
    """Return the ARNs of policies directly attached to a user and ARNs of policies attached to
    groups the user is in.
    """
    group_policies = []
    for group_name in user_details["GroupList"]:
        group_policies.extend([policy['PolicyArn'] for policy in group_details[group_name]['AttachedManagedPolicies']])
    return group_policies


def get_account_details(iam_client: Type[botocore.client.BaseClient]) -> dict[str: dict]:
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": []}
    # noinspection PyArgumentList
    paginator = iam_client.get_paginator('get_account_authorization_details')
    page_iterator = paginator.paginate(Filter=['User', 'Role', 'Group'])
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

    return details


def audit_account_access(sso_session: boto3.Session) -> Optional[Account]:
    """Audit access for a single account."""
    iam_client = sso_session.client('iam')
    try:
        account_details = get_account_details(iam_client)
    except NoAccessException:
        return None
    new_account = Account(sso_session.profile_name, account_details)

    for policy_name, policy in new_account.policies.items():
        policy.get_policy_details(iam_client)

    return new_account


def save_account_details(account_details: dict):
    with open(OUTPUT_NAME, 'wb') as output_file:
        dill.dump(account_details, output_file)


def load_account_details():
    with open(OUTPUT_NAME, 'rb') as input_file:
        return dill.load(input_file)


def audit_all_account_access(sso_profile_name: str):
    """Loop through all the accounts in a single SSO profile, getting IAM information for each one."""
    profile_names = get_profiles_in_sso(sso_profile_name)
    accounts = []
    for account_name in tqdm.tqdm(profile_names[0:3]):
        session = boto3.Session(profile_name=account_name)
        account = audit_account_access(session)
        accounts.append(account)
    generate_report(sso_profile_name, accounts)


if __name__ == "__main__":
    audit_all_account_access("old-organisation")
