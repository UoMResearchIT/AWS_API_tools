from __future__ import annotations
from typing import Type, TYPE_CHECKING

import boto3
import botocore.client
import botocore.errorfactory

if TYPE_CHECKING:
    from access_audit.access_audit import Account, NoAccessException


class AccessInformation:
    def __init__(self, accounts: list[Account]):
        self.accounts: list[Account] = accounts
        self.permission_sets = dict[str: PermissionSet]
        self.groups = dict[str: Group]
        self.users = dict[str: SSOUser]


class PermissionSet:
    def __init__(self, name: str, arn: str):
        self.name: str = name
        self.arn: str = arn
        self.managed_policies = []
        self.customer_policies = []
        self.inline_policy = ""
        self.permission_sets: list[PermissionSet] = []

    def __repr__(self):
        return f"{self.arn}"


class Assignment:
    def __init__(self, permission_set: PermissionSet, account: Account):
        self.permission_set: PermissionSet = permission_set
        self.account: Account = account
        self.members: list[SSOUser | Group] = []


class Group:
    def __init__(self, name: str, group_id: str):
        self.name: str = name
        self.id: str = group_id
        self.members: list[SSOUser] = []
        self.assignments: list[Assignment] = []

    def __repr__(self):
        return f"Group: {self.name}"


class SSOUser:
    def __init__(self, username: str, name: str, user_id: str):
        self.username: str = username
        self.name: str = name
        self.id: str = user_id
        self.groups: list[Group] = []
        self.assignments: list[Assignment] = []

    def __repr__(self):
        return f"SSOUser: {self.name}"


def get_permission_set(instance_arn: str, set_arn: str, sso_client: Type[botocore.client.BaseClient]) -> PermissionSet:
    """Given the ARN of a permission set, get details of the policies in that permission set."""
    set_name = sso_client.describe_permission_set(InstanceArn=instance_arn,
                                                  PermissionSetArn=set_arn)["PermissionSet"]["Name"]
    new_set = PermissionSet(set_name, set_arn)
    # Get managed policies
    # noinspection PyArgumentList
    paginator = sso_client.get_paginator("list_managed_policies_in_permission_set")
    page_iterator = paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=set_arn)
    for page in page_iterator:
        new_set.managed_policies.extend(page["AttachedManagedPolicies"])
    # Get customer policies
    # noinspection PyArgumentList
    paginator = sso_client.get_paginator("list_customer_managed_policy_references_in_permission_set")
    page_iterator = paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=set_arn)
    for page in page_iterator:
        new_set.customer_policies.extend(page["CustomerManagedPolicyReferences"])
    new_set.inline_policy = sso_client.get_inline_policy_for_permission_set(InstanceArn=instance_arn,
                                                                            PermissionSetArn=set_arn)["InlinePolicy"]
    return new_set


def audit_sso_access(session: boto3.session, accounts: list[Account]) -> AccessInformation:
    """Get information about IAM Identity Center identities for a master AWS account."""
    region_name = "eu-west-2"
    sso_client = session.client("sso-admin", region_name=region_name)
    identity_client = session.client("identitystore", region_name=region_name)
    access_info = AccessInformation(accounts)

    identity_store_id, instance_arn = get_instance_info(region_name, sso_client)

    access_info.permission_sets = get_permission_sets(instance_arn, sso_client)
    access_info.users = get_sso_users(identity_client, identity_store_id)
    access_info.groups = get_sso_groups(identity_client, identity_store_id, access_info.users)

    get_assignments(instance_arn, sso_client, access_info)

    return access_info


def get_assignments(instance_arn: str, sso_client: Type[botocore.client.BaseClient], access_info: AccessInformation):
    """Gets assignments of permission sets and users to accounts. The function adds the assignments directly to the
    User, PermissionSet and Account objects and so does not return a list of the Assignments.
    """
    for account in access_info.accounts:
        account_sets = get_applied_permission_sets(sso_client, instance_arn, account.id)

        for permission_set_arn in account_sets:
            account_assignments = sso_client.list_account_assignments(InstanceArn=instance_arn, AccountId=account.id,
                                                                      PermissionSetArn=permission_set_arn)[
                "AccountAssignments"]
            new_assignment = Assignment(access_info.permission_sets[permission_set_arn], account)
            for assignment in account_assignments:
                if assignment["PrincipleType"] == "GROUP":
                    new_assignment.members.append(access_info.groups["PrincipleID"])
                    access_info.groups["PrincipleID"].assignments.append(new_assignment)
                else:
                    new_assignment.members.append(access_info.users["PrincipleID"])
                    access_info.users["PrincipleID"].assignments.append(new_assignment)
            access_info.permission_sets[permission_set_arn].assignments.append(new_assignment)
            account.assignments.append(new_assignment)


def get_instance_info(region_name: str, sso_client: Type[botocore.client.BaseClient]):
    """Given a region name, get information on the identity store instance."""
    try:
        instance = sso_client.list_instances()["Instances"][0]
        instance_arn = instance["InstanceArn"]
        identity_store_id = instance["IdentityStoreId"]
    except botocore.errorfactory.BaseClientExceptions.ClientError:
        raise NoAccessException(f"No access to SSO-Admin - check SSO is present in requested region: {region_name}")
    return identity_store_id, instance_arn


def get_permission_sets(instance_arn: str, sso_client: Type[botocore.client.BaseClient]) -> dict[str: PermissionSet]:
    """Given an identity store instance, get a list of the users."""
    permission_set_ids = []
    # noinspection PyArgumentList
    paginator = sso_client.get_paginator("list_permission_sets")
    page_iterator = paginator.paginate(InstanceArn=instance_arn)
    for page in page_iterator:
        permission_set_ids.extend(page["PermissionSets"])
    return {set_id: get_permission_set(instance_arn, set_id, sso_client) for set_id in permission_set_ids}


def get_applied_permission_sets(sso_client: Type[botocore.client.BaseClient], instance_arn: str,
                                account_id: str) -> list[str]:
    """List the permission sets that are applied to an account."""
    account_permission_sets = []
    # noinspection PyArgumentList
    paginator = sso_client.get_paginator("list_permission_sets_provisioned_to_account")
    page_iterator = paginator.paginate(InstanceArn=instance_arn, AccountId=account_id)
    for page in page_iterator:
        account_permission_sets.extend(page["PermissionSets"])
    return account_permission_sets


def get_sso_users(identity_client: Type[botocore.client.BaseClient], identity_store_id: str) -> dict[str: SSOUser]:
    """Given an identity store, get a list of the users."""
    users = []
    # noinspection PyArgumentList
    paginator = identity_client.get_paginator('list_users')
    page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
    for page in page_iterator:
        users.extend(page["Users"])
    users = {user["UserId"]: SSOUser(user["UserName"], user["DisplayName"], user["UserId"]) for user in users}
    return users


def get_sso_groups(identity_client: Type[botocore.client.BaseClient], identity_store_id: str,
                   users: dict[SSOUser]) -> dict[str: Group]:
    """Given an identity store and a region, get a list of the groups in that region."""
    groups = []
    # noinspection PyArgumentList
    paginator = identity_client.get_paginator('list_groups')
    page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
    for page in page_iterator:
        groups.extend(page["Groups"])
    groups = {group["GroupId"]: Group(group["DisplayName"], group["GroupId"]) for group in groups}

    for group_id, group in groups.items():
        memberships = []
        # noinspection PyArgumentList
        paginator = identity_client.get_paginator('list_group_memberships')
        page_iterator = paginator.paginate(IdentityStoreId=identity_store_id, GroupId=group_id)
        for page in page_iterator:
            memberships.extend(page["GroupMemberships"])
        for membership in memberships:
            group.members.append(users[membership["MemberId"]["UserId"]])
            users[membership["MemberId"]["UserId"]].groups.append(group)

    return groups
