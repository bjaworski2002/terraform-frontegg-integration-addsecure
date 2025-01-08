#!/usr/bin/env python3

import sys
import json
import requests

def get_access_token(client_id, secret_key, api_base_url):
    url = f"{api_base_url}/auth/vendor/"
    payload = {
        "clientId": client_id,
        "secret": secret_key
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        token = data.get("token") or data.get("accessToken")
        if not token:
            raise Exception("Token not found in the response.")
        return token
    else:
        raise Exception(f"Failed to fetch token. Status: {response.status_code}, Response: {response.text}")

def get_permissions(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/permissions/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        raise Exception(f"Failed to fetch permissions. Status: {response.status_code}, Response: {response.text}")

def get_categories(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        raise Exception(f"Failed to fetch categories. Status: {response.status_code}, Response: {response.text}")

def get_roles(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/roles/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch roles. Status: {response.status_code}, Response: {response.text}")

def get_features(token, api_base_url, environment_id):
    all_features = []      # To store all fetched features
    offset = 0             # Starting offset
    limit = 10            # Number of items per request (adjust as needed)
    max_iterations = 1000  # Safety to prevent infinite loops
    iterations = 0

    while True:
        iterations += 1
        if iterations > max_iterations:
            raise Exception("Exceeded maximum iterations while fetching features. Possible infinite loop.")

        # Construct the URL with query parameters for pagination
        url = f"{api_base_url}/entitlements/resources/features/v1?offset={offset}&limit={limit}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            # Uncomment the next line if 'frontegg-tenant-id' is required
            # "frontegg-tenant-id": environment_id,
        }

        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP request failed: {e}")

        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            all_features.extend(items)

            has_next = data.get("hasNext", False)
            if has_next:
                offset += limit  # Move to the next set of items
            else:
                break  # All features have been fetched
        else:
            raise Exception(f"Failed to fetch features. Status: {response.status_code}, Response: {response.text}")

    return all_features


def main():
    try:
        input_data = json.load(sys.stdin)
        client_id = input_data.get("client_id")
        secret_key = input_data.get("secret_key")
        api_base_url = input_data.get("api_base_url")
        environment_id = input_data.get("environment_id")

        if not all([client_id, secret_key, api_base_url, environment_id]):
            raise Exception("Missing one or more required input parameters.")

        token = get_access_token(client_id, secret_key, api_base_url)

        permissions = get_permissions(token, api_base_url, environment_id)
        categories = get_categories(token, api_base_url, environment_id)
        roles = get_roles(token, api_base_url, environment_id)
        features = get_features(token, api_base_url, environment_id)

        permissions_json_str = json.dumps(permissions)
        categories_json_str = json.dumps(categories)
        roles_json_str = json.dumps(roles)
        features_json_str = json.dumps(features)

        output = {
            "permissions": permissions_json_str,
            "categories": categories_json_str,
            "roles": roles_json_str,
            "features": features_json_str
        }
        print(json.dumps(output))
    except Exception as e:
        error_output = {"error": str(e)}
        print(json.dumps(error_output))
        sys.exit(1)

if __name__ == "__main__":
    main()
