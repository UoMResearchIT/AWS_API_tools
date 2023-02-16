from __future__ import annotations

import json
import pathlib
from typing import Type

import botocore.client
import dill


POLICY_WORDING_CACHE: dict[str: str] = {}


class Policy:
    """A Policy is an IAM object which can be attached to an identity to control what access it has to resources.

    :ivar name: The friendly name of the policy
    :ivar text: The wording of the policy.
    :ivar arn: The Amazon Resource Name of the policy.
    :ivar version: The version of the policy.
    :ivar description: A textual description of the policy.
    :ivar aws_managed: Whether the policy is a standard AWS provided one, or a custom one.
    """
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
        """Get details for the policy.

        Policy details are not downloaded with the get_account_authorization_details API request,
        since there is a lot of duplication. Policy wording is instead downloaded once for each policy once and cached.
        """
        global POLICY_WORDING_CACHE

        cache_path = pathlib.Path("policy_cache.bin")

        if not POLICY_WORDING_CACHE:
            if cache_path.exists():
                with open(cache_path, 'rb') as input_file:
                    POLICY_WORDING_CACHE = dill.load(input_file)

        if self.arn not in POLICY_WORDING_CACHE:
            policy = iam_client.get_policy(PolicyArn=self.arn)["Policy"]
            self.name = policy["PolicyName"]
            self.version = policy["DefaultVersionId"]
            if "Description" in policy:
                self.description = policy["Description"]
            policy_text = iam_client.get_policy_version(PolicyArn=self.arn, VersionId=self.version)
            self.text = json.dumps(policy_text["PolicyVersion"]["Document"], indent=2).replace("\n", "<br>")
            POLICY_WORDING_CACHE[self.arn] = self

            with open(cache_path, 'wb') as output_file:
                dill.dump(POLICY_WORDING_CACHE, output_file)

        else:
            self.name = POLICY_WORDING_CACHE[self.arn].name
            self.version = POLICY_WORDING_CACHE[self.arn].version
            self.description = POLICY_WORDING_CACHE[self.arn].description
            self.text = POLICY_WORDING_CACHE[self.arn].text


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
