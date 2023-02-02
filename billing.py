import boto3
import dateparser


def get_organisation_accounts(session: boto3.Session) -> list[dict]:
    """Get a list of accounts in the organisation."""
    client = session.client('organizations')
    response = client.list_accounts()
    accounts = response["Accounts"]
    while "NextToken" in response:
        response = client.list_accounts(NextToken=response["NextToken"])
        accounts.extend(response["Accounts"])
    return accounts


def get_cost_report(session: boto3.Session, start: str, end: str, accounts: list[str]) -> dict:
    """Get a monthly cost report for each account in `accounts`.
    :param session: A boto3 session.
    :param start: The start date for the cost report.
    :param end: The end date for the cost report.
    :param accounts: A list of account IDs to get costs for.
    """
    client = session.client('ce')  # Cost explorer session
    cost_data = client.get_cost_and_usage(TimePeriod={"Start": start, "End": end},
                                          Granularity="MONTHLY",
                                          Metrics=["NetUnblendedCost"],
                                          Filter={"Dimensions": {"Key": "LINKED_ACCOUNT",
                                                                 "Values": accounts}},
                                          GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}])
    return cost_data


def cost_to_csv(account_data: list[dict], cost_data: dict):
    """Write the cost data to a CSV file."""
    with open("cost.csv", 'w') as output_file:
        output_file.write(f"Account ID,Account Name,Root Email,Status,")
        # Write header line to file.
        for month in cost_data["ResultsByTime"]:
            output_file.write(f"{dateparser.parse(month['TimePeriod']['Start'],['%Y-%m-%d']).strftime('%b %Y')},")
        output_file.write("\n")
        # Sort accounts by ID so that vlookup works in Excel
        account_data.sort(key=lambda d: d['Id'])
        # Write one line per account.
        for account in account_data:
            output_file.write(f"{account['Id']},{account['Name']},{account['Email']},{account['Status']},")
            for month in cost_data["ResultsByTime"]:
                bill_amount = 0
                for group in month['Groups']:
                    if account['Id'] in group["Keys"]:
                        bill_amount = group["Metrics"]["NetUnblendedCost"]["Amount"]
                        break
                output_file.write(f"{bill_amount},")
            output_file.write(f"{'-' * 30}\n")


def generate_billing_report(sso_profile_name: str):
    session = boto3.Session(profile_name=sso_profile_name)
    accounts = get_organisation_accounts(session)
    cost_data = get_cost_report(session, "2022-09-01", "2023-01-01", [account['Id'] for account in accounts])
    cost_to_csv(accounts, cost_data)


if __name__ == "__main__":
    generate_billing_report("cfhh")
