# Get a list of all the accounts in an organisation and add an SSO section to the config ini file for each of them.

import boto3
import configparser

from billing import get_organisation_accounts
from config import read_config, write_config


def add_accounts_to_profile(accounts: list[dict], config: configparser.ConfigParser, sso_profile_name: str):
    """Add profiles for all accounts in the organisation to the profile file if they are not already present."""
    # Get a list of the account ids that already have a profile in the config file.
    accounts = {account["Id"]: account for account in accounts if account["Status"] == "ACTIVE"}
    current_profile_ids = [config[section]["sso_account_id"] for section in config.sections()
                           if section.startswith("profile")]
    # Remove any accounts from the to add list if they are already in the config file
    for account_id in current_profile_ids:
        accounts.pop(account_id, None)
    for account in accounts.values():
        account_name = account['Name']
        if " " in account_name:
            account_name = f"'{account_name}'"
        section_name = f"profile {sso_profile_name}-{account_name}"
        config.add_section(section_name)
        config[section_name]["sso_session"] = f"{sso_profile_name}-sso"
        config[section_name]["sso_account_id"] = account["Id"]
        config[section_name]["sso_role_name"] = "AWSAdministratorAccess"
    return config


def remove_accounts_from_profile(config: configparser.ConfigParser, sso_profile_name: str) -> configparser.ConfigParser:
    """Remove any previous profiles in the config that are associated with the sso_session."""
    for section in config.sections():
        if section.startswith(f"profile-{sso_profile_name}") and section != f"profile-{sso_profile_name}":
            if config[section]["sso_session"] == config[f"profile {sso_profile_name}"]["sso_session"]:
                config.remove_section(section)
    return config


def update_credentials(sso_profile_name: str):
    session = boto3.Session(profile_name=sso_profile_name)
    config = read_config()
    accounts = get_organisation_accounts(session)
    if " " in sso_profile_name:
        sso_profile_name = f"'{sso_profile_name}'"
    config = remove_accounts_from_profile(config, sso_profile_name)
    config = add_accounts_to_profile(accounts, config, sso_profile_name)
    write_config(config)


if __name__ == "__main__":
    update_credentials("old-organisation")