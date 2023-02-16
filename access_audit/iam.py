from __future__ import annotations
from typing import TYPE_CHECKING, Type, Optional

import boto3
import botocore.client
import botocore.exceptions


from policy import get_group_policies, Policy

if TYPE_CHECKING:
    from sso import Group, Assignment


class NoAccessException(Exception):
    pass

class IAMUser:
    """An object describing an IAM user.

    :ivar groups: A list of `Group`s that a user is a member of.
    :ivar policies: A list of `Policy` objects representing policies that are attached to the user or to groups that
      the user is a member of.
    """
    def __init__(self, username: str, account_details: dict):
        self.username: str = username

        user_details = account_details["Users"][self.username]
        self.groups: list[Group] = user_details["GroupList"]

        self.policies: list[Policy] = [Policy(policy["PolicyArn"], "User") for
                                                policy in user_details["AttachedManagedPolicies"]]
        self.policies.extend(get_group_policies(user_details, account_details["Groups"]))


class Account:
    """An object representing an AWS account.

    :ivar name: The friendly name of the Account.
    :ivar id: The numerical account ID.
    :ivar iam_users: A list of `IAMUser`s within the account.
    :ivar assignments: A list of `assignments` which list which identities policies are applied to.
    :ivar num_permission_sets: A count of the total number of SSO permission sets in the account.
    """
    def __init__(self, name: str, account_id: str, account_details: dict):
        self.name: str = name
        self.id: str = account_id
        self.iam_users: list[IAMUser] = []
        self.assignments: list[Assignment] = []
        self.num_permission_sets: int = 0

        self.iam_users = [(IAMUser(username, account_details)) for username in account_details["Users"]]


def get_account_details(iam_client: Type[botocore.client.BaseClient]) -> dict[str, dict]:
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


def audit_account_iam(sso_session: boto3.Session) -> Optional[Account]:
    """Get information about IAM identities for a single AWS account."""
    iam_client = sso_session.client('iam')
    try:
        account_details = get_account_details(iam_client)
    except NoAccessException:
        return None
    account_id = sso_session.client('sts').get_caller_identity()["Account"]
    new_account = Account(sso_session.profile_name, account_id, account_details)

    for user in new_account.iam_users:
        for policy in user.policies:
            policy.get_policy_details(iam_client)

    return new_account
