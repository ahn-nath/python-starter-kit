from msal import ConfidentialClientApplication
import requests

# Azure AD app credentials
client_id = None
client_secret = None
tenant_id = None

# Initialize MSAL app
authority = f"https://login.microsoftonline.com/{tenant_id}"
app = ConfidentialClientApplication(
    client_id,
    authority=authority,
    client_credential=client_secret
)

# Get a token for Microsoft Graph
token_response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
access_token = token_response['access_token']

# List of group IDs to map
group_ids_ = [
    'fa419a30-acc4-4895-9fc6-cfce35e84b9c',  # Student
    'group-id-2',
]

# Prepare headers
headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}


def get_group_names(group_ids):
    """
        This function will take a list of group IDs and return a dictionary mapping the IDs to the names.
        It will also print the names of the groups.
        :return: A dictionary group_id_to_name[group_id] = groupName
    """
    # Query group details
    group_id_to_name = {}

    for group_id in group_ids:
        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            group = response.json()
            group_id_to_name[group_id] = group.get('displayName', 'Unknown')
        else:
            group_id_to_name[group_id] = f"Error: {response.status_code}"

    # Print result
    for gid, name in group_id_to_name.items():
        print(f"{gid} → {name}")

    return group_id_to_name


if __name__ == "__main__":
    get_group_names(group_ids_)
