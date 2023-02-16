from __future__ import annotations

import json
import pathlib
from typing import Type

import botocore.client
import dill


POLICY_DETAILS_CACHE: dict[str, Policy] = {}
ATTACHMENT_TYPES = ["Group", "User", "Inline"]

class Policy:
    """A Policy is an IAM object which can be attached to an identity to control what access it has to resources.

    :ivar name: The friendly name of the policy
    :ivar attachment_type: Whether the policy is attached to a group, a user or inline.
    :ivar text: The wording of the policy.
    :ivar arn: The Amazon Resource Name of the policy.
    :ivar version: The version of the policy.
    :ivar description: A textual description of the policy.
    :ivar aws_managed: Whether the policy is a standard AWS provided one, or a custom one.
    """
    def __init__(self, arn: str, attachment_type: str):
        if attachment_type not in ATTACHMENT_TYPES:
            raise SyntaxError(f"Invalid attachment type '{attachment_type}' when instantiating policy")

        self.arn: str = arn
        self.attachment_type: str = attachment_type
        if self.arn.startswith("arn:aws:iam::aws:policy"):
            self.aws_managed = True
        else:
            self.aws_managed = False

        self.name: str = ""
        self.text: str = ""
        self.version: str = ""
        self.description: str = ""


    def __repr__(self):
        return f"{self.arn}"

    def get_policy_details(self, iam_client: Type[botocore.client.BaseClient]):
        """Get details for the policy.

        Policy details are not downloaded with the get_account_authorization_details API request,
        since there is a lot of duplication. Policy details are instead downloaded once for each policy and cached.
        """
        global POLICY_DETAILS_CACHE

        cache_path = pathlib.Path("policy_cache.bin")

        if not POLICY_DETAILS_CACHE:
            if cache_path.exists():
                with open(cache_path, 'rb') as input_file:
                    POLICY_DETAILS_CACHE = dill.load(input_file)

        if self.arn not in POLICY_DETAILS_CACHE:
            policy = iam_client.get_policy(PolicyArn=self.arn)["Policy"]
            self.name = policy["PolicyName"]
            self.version = policy["DefaultVersionId"]
            if "Description" in policy:
                self.description = policy["Description"]
            policy_text = iam_client.get_policy_version(PolicyArn=self.arn, VersionId=self.version)
            self.text = json.dumps(policy_text["PolicyVersion"]["Document"], indent=2).replace("\n", "<br>")
            POLICY_DETAILS_CACHE[self.arn] = self

            with open(cache_path, 'wb') as output_file:
                dill.dump(POLICY_DETAILS_CACHE, output_file)

        else:
            self.name = POLICY_DETAILS_CACHE[self.arn].name
            self.text = POLICY_DETAILS_CACHE[self.arn].text
            self.version = POLICY_DETAILS_CACHE[self.arn].version
            self.description = POLICY_DETAILS_CACHE[self.arn].description


def get_group_policies(user_details: dict, group_details: dict) -> list[Policy]:
    """Return a list of `Policy` representing policies attached to groups the user is in."""
    group_policies = []
    for group_name in user_details["GroupList"]:
        group_policies.extend([policy['PolicyArn'] for policy in group_details[group_name]['AttachedManagedPolicies']])
    return [Policy(arn, "Group") for arn in group_policies]
