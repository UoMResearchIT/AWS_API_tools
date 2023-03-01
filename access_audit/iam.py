from __future__ import annotations
from typing import TYPE_CHECKING, Type, Optional

import boto3
import botocore.client
import botocore.exceptions

from policy import get_group_policies, Policy

if TYPE_CHECKING:
    from sso import Group, Assignment
    from config import Profile


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
    :ivar access_error: True if it is not possible to read account details.
    """
    def __init__(self, name: str, account_id: str, account_details: Optional[dict]):
        self.name: str = name
        self.id: str = account_id
        self.iam_users: list[IAMUser] = []
        self.assignments: list[Assignment] = []
        self.num_permission_sets: int = 0
        self.access_error = False

        if account_details:
            self.iam_users = [(IAMUser(username, account_details)) for username in account_details["Users"]]
        else:
            self.access_error = True


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


def audit_account_iam(profile: Profile) -> Optional[Account]:
    """Get information about IAM identities for a single AWS account."""

    # IAM is global so don't need to specify region.
    session = boto3.Session(profile_name=profile.profile_name)
    iam_client = session.client('iam')
    try:
        account_details = get_account_details(iam_client)
    except NoAccessException:
        account_details = None

    new_account = Account(profile.friendly_name, profile.account_id, account_details)

    for user in new_account.iam_users:
        for policy in user.policies:
            policy.get_policy_details(iam_client)

    return new_account
