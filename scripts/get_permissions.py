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

def main():
    try:
        # Read input from Terraform
        input_data = json.load(sys.stdin)
        client_id = input_data.get("client_id")
        secret_key = input_data.get("secret_key")
        api_base_url = input_data.get("api_base_url")
        environment_id = input_data.get("environment_id")

        if not all([client_id, secret_key, api_base_url, environment_id]):
            raise Exception("Missing one or more required input parameters.")

        # Authenticate and get token
        token = get_access_token(client_id, secret_key, api_base_url)

        # Fetch permissions
        permissions = get_permissions(token, api_base_url, environment_id)
        # Fetch categories
        categories = get_categories(token, api_base_url, environment_id)

        # Encode them as JSON strings
        permissions_json_str = json.dumps(permissions)
        categories_json_str = json.dumps(categories)

        # Output both permissions and categories as strings
        output = {
            "permissions": permissions_json_str,
            "categories": categories_json_str
        }
        print(json.dumps(output))
    except Exception as e:
        # Output the error in a way Terraform can understand
        error_output = {"error": str(e)}
        print(json.dumps(error_output))
        sys.exit(1)

if __name__ == "__main__":
    main()
