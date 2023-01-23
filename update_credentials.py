# Get a list of all the accounts in an organisation and add an SSO section to the config ini file for each of them.
import pathlib

import boto3
import configparser

from billing import get_organisation_accounts

CONFIG_PATH = pathlib.Path.home() / (".aws/config")


def read_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return config


def write_config(config: configparser.ConfigParser):
    with open(CONFIG_PATH, 'w') as output_file:
        config.write(output_file)


def add_missing_accounts(accounts: list[dict], config: configparser.ConfigParser, sso_profile_name: str):
    """Add profiles for all accounts in the organisation to the profile file if they are not already present."""
    master_account_id = config[f"profile {sso_profile_name}"]["sso_account_id"]
    accounts = {account["Id"]: account for account in accounts if account["Status"] == "ACTIVE"}
    # Get a list of the account ids that already have a profile in the config file.
    current_profile_ids = [config[section]["sso_account_id"] for section in config.sections()
                           if section.startswith("profile")]
    # Remove any accounts from the list if they are already in the config file
    for account_id in current_profile_ids:
        accounts.pop(account_id, None)
    for account in accounts.values():
        config.add_section(f"profile {account['Name']}")
        config[f"profile {account['Name']}"]["sso_session"] = f"{sso_profile_name}-sso"
        config[f"profile {account['Name']}"]["sso_account_id"] = account["Id"]
        config[f"profile {account['Name']}"]["sso_role_name"] = "AWSAdministratorAccess"
    return config


def update_credentials(sso_profile_name: str):
    session = boto3.Session(profile_name=sso_profile_name)
    current_settings = read_config()
    accounts = get_organisation_accounts(session)
    config = add_missing_accounts(accounts, current_settings, sso_profile_name)
    write_config(config)


if __name__ == "__main__":
    update_credentials("old-organisation")