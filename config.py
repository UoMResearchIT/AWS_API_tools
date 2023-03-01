import configparser
import pathlib

import boto3

CONFIG_PATH = pathlib.Path.home() / ".aws/config"

class Profile:
    """An SSO profile that allows access to an account."""
    def __init__(self, profile_name: str, friendly_name: str, account_id: str):
        self.profile_name = profile_name
        self.friendly_name = friendly_name
        self.account_id = account_id
        self.status = "unknown"

    def __repr__(self):
        return f"Profile - {self.friendly_name}"


def read_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return config


def write_config(config: configparser.ConfigParser):
    with open(CONFIG_PATH, 'w') as output_file:
        config.write(output_file)


def get_profiles_in_sso(sso_profile_name: str) -> dict[str: str]:
    """Given the name of a profile in the config file, return a dict with profile names and account numbers of other
    profiles that use the same SSO login.

    This is useful because given the name of an SSO profile, it will fetch all accounts accessible to that profile.
    """
    config = read_config()
    if " " in sso_profile_name:
        sso_profile_name = f"'{sso_profile_name}'"
    if not sso_profile_name.startswith("profile "):
        sso_profile_name = "profile " + sso_profile_name
    profile_names = [name for name in config.sections() if name.startswith("profile")]
    profile_names = [name for name in profile_names if
                     config[name]["sso_session"] == config[sso_profile_name]["sso_session"]]

    profiles = {}
    for name in profile_names:
        # Remove any quotes and 'profile ' from the profile name
        simple_name = name.replace("'", "").removeprefix("profile ")
        profiles[simple_name] = config[name]["sso_account_id"]

    return profiles


def populate_profiles(profile_details: dict[str: str]) -> list[Profile]:
    print("Getting SSO profile details.")
    management_profile_name = [name for name in profile_details if name.startswith("management")]

    if not management_profile_name:
        # If there is no management account, we cannot get information about the friendly name
        profiles = [Profile(name, name, account_id) for name, account_id in profile_details.items()]
    elif len(management_profile_name) > 1:
        raise SyntaxError("More than one profile name in AWS config file starts with 'management-'.")
    else:
        session = boto3.Session(profile_name=management_profile_name[0])
        org_client = session.client("organizations")

        profiles = []
        for profile_name in profile_details:
            account_description = org_client.describe_account(AccountId=profile_details[profile_name])["Account"]
            new_profile = Profile(profile_name, account_description["Name"], account_description["Id"])
            new_profile.status = account_description["Status"]
            profiles.append(new_profile)
    print("Finished getting SSO profile details.")
    return profiles
