from __future__ import annotations
from typing import TYPE_CHECKING, Type, Optional

import boto3
import botocore.client
import botocore.exceptions


from policy import get_group_policy_arns, get_policy

if TYPE_CHECKING:
    from sso import Group, Assignment
    from policy import Policy


class NoAccessException(Exception):
    pass

class IAMUser:
    """An object describing an IAM user.

    :ivar groups: A list of `Group`s that a user is a member of.
    :ivar attached_policies: A list of `Policy` objects representing policies directly attached to the user.
    :ivar group_policies: A list of `Policy` objects representing policies that apply to the user as a result of group
      membership.
    """
    def __init__(self, username: str, account_details: dict, policy_cache: dict[str: Policy]):
        self.username: str = username

        user_details = account_details["Users"][self.username]
        self.groups: list[Group] = user_details["GroupList"]

        attached_policy_arns: list[str] = [policy["PolicyArn"] for policy in user_details["AttachedManagedPolicies"]]
        group_policy_arns: list[str] = get_group_policy_arns(user_details, account_details["Groups"])

        self.attached_policies: list[Policy] = [get_policy(arn, policy_cache) for arn in attached_policy_arns]
        self.group_policies: list[Policy] = [get_policy(arn, policy_cache) for arn in group_policy_arns]


class Account:
    """An object representing an AWS account.

    :ivar name: The friendly name of the Account.
    :ivar id: The numerical account ID.
    :ivar iam_users: A list of `IAMUser`s within the account.
    :ivar policies: A list of `Policy` that are assigned to identities in the account.
    :ivar assignments: A list of `assignments` which list which identities policies are applied to.
    :ivar num_permission_sets: A count of the total number of SSO permission sets in the account.
    """
    def __init__(self, name: str, account_id: str, account_details: dict):
        self.name: str = name
        self.id: str = account_id
        self.iam_users: list[IAMUser] = []
        self.policies: dict[str: Policy] = {}
        self.assignments: list[Assignment] = []
        self.num_permission_sets: int = 0

        self.iam_users = [(IAMUser(username, account_details, self.policies)) for username in account_details["Users"]]


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


def audit_account_iam(sso_session: boto3.Session) -> Optional[Account]:
    """Get information about IAM identities for a single AWS account."""
    iam_client = sso_session.client('iam')
    try:
        account_details = get_account_details(iam_client)
    except NoAccessException:
        return None
    account_id = sso_session.client('sts').get_caller_identity()["Account"]
    new_account = Account(sso_session.profile_name, account_id, account_details)

    for policy_name, policy in new_account.policies.items():
        policy.get_policy_details(iam_client)

    return new_account
