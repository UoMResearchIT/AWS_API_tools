from __future__ import annotations
from typing import TYPE_CHECKING

import boto3
import jinja2
import dill
import tqdm

from iam import audit_account_iam
from sso import audit_sso_access, sort_report_data
from config import get_profiles_in_sso

if TYPE_CHECKING:
    from sso import AccessInformation

OUTPUT_NAME = "debug.bin"


def generate_report(sso_profile_name: str, access_info: AccessInformation):
    env = jinja2.Environment(loader=jinja2.PackageLoader("access_audit"), autoescape=jinja2.select_autoescape(),
                             undefined=jinja2.StrictUndefined, extensions=["jinja2.ext.do"])
    template = env.get_template("report_template.html")
    report = template.render(sso_profile_name=sso_profile_name, access_info=access_info)

    with open("iam_report.html", 'w') as output_file:
        output_file.write(report)


def save_account_details(accounts: AccessInformation):
    with open(OUTPUT_NAME, 'wb') as output_file:
        dill.dump(accounts, output_file)


def load_account_details():
    with open(OUTPUT_NAME, 'rb') as input_file:
        return dill.load(input_file)


def audit_access(sso_profile_name: str, debug=False):
    """Loop through all the accounts in a single SSO profile, getting user and access information for each one."""
    if not debug:
        profile_names = get_profiles_in_sso(sso_profile_name)
        accounts = []
        for account_name in tqdm.tqdm(profile_names[0:3]):
            # IAM is global so don't need to specify region.
            session = boto3.Session(profile_name=account_name)
            account = audit_account_iam(session)
            accounts.append(account)
        print("Completed iam analysis.")

        session = boto3.Session(profile_name=sso_profile_name)
        account_info = audit_sso_access(session, accounts)
        account_info = sort_report_data(account_info)
        save_account_details(account_info)

    account_info = load_account_details()
    generate_report(sso_profile_name, account_info)


if __name__ == "__main__":
    audit_access("old-organisation", True)
