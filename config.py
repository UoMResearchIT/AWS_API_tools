import configparser
import pathlib

CONFIG_PATH = pathlib.Path.home() / ".aws/config"


def read_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return config


def write_config(config: configparser.ConfigParser):
    with open(CONFIG_PATH, 'w') as output_file:
        config.write(output_file)


def get_profiles_in_sso(sso_profile_name: str):
    """Given the name of a profile in the config file, get names of other profiles that use the same SSO login.

    This is useful because given the name of an account in an organisation, it will fetch all other accounts in
    the organisation to loop through.
    """
    config = read_config()
    if not sso_profile_name.startswith("profile "):
        sso_profile_name = "profile " + sso_profile_name
    profile_names = [name for name in config.sections() if name.startswith("profile")]
    profile_names = [name for name in profile_names if
                     config[name]["sso_session"] == config[sso_profile_name]["sso_session"]]
    # Remove "profile " from the beginning of the name
    return [name.removeprefix("profile ") for name in profile_names]
