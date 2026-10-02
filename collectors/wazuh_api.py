import getpass
import requests

WAZUH_URL = "https://10.89.174.46:55000"


def get_token(username, password):
    url = f"{WAZUH_URL}/security/user/authenticate"

    response = requests.post(
        url,
        auth=(username, password),
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    return response.json()["data"]["token"]


def get_api_info(token):
    response = requests.get(
        f"{WAZUH_URL}/",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    return response.json()

def get_agents(token):
    response = requests.get(
        f"{WAZUH_URL}/agents",
        headers={"Authorization": f"Bearer {token}"},
        params={"limit": 100},
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    return response.json()

if __name__ == "__main__":

    print("=== WAZUH API CONNECTION TEST ===")

    username = input("Wazuh API username: ")
    password = getpass.getpass("Wazuh API password: ")

    token = get_token(username, password)

    print("Authentication: SUCCESS")

    info = get_api_info(token)

    print("API connection: SUCCESS")
    print(f"API version: {info['data']['api_version']}")
    print(f"Hostname: {info['data']['hostname']}")
    agents = get_agents(token)

    print("\n=== WAZUH AGENTS ===")

    for agent in agents["data"]["affected_items"]:
        print(
            f"ID: {agent['id']} | "
            f"Name: {agent['name']} | "
            f"IP: {agent.get('ip', 'N/A')} | "
            f"Status: {agent['status']}"
        )
