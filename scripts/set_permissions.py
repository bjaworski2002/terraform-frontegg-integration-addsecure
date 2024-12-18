#!/usr/bin/env python3

import sys
import json
import requests
import argparse

def get_access_token(environment_id, secret_key, api_base_url):
    url = f"{api_base_url}/auth/vendor/"
    payload = {
        "clientId": environment_id,
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

def fetch_permissions(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/permissions/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        permissions = response.json()
        # Filter permissions where fePermission is False
        filtered_permissions = [perm for perm in permissions if not perm.get("fePermission", True)]
        return filtered_permissions
    else:
        raise Exception(f"Failed to fetch permissions. Status: {response.status_code}, Response: {response.text}")

def fetch_categories(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        categories = response.json()
        # Filter categories where feCategory is False
        filtered_categories = [cat for cat in categories if not cat.get("feCategory", True)]
        return filtered_categories
    else:
        raise Exception(f"Failed to fetch categories. Status: {response.status_code}, Response: {response.text}")

def delete_permission(token, api_base_url, environment_id, permission_id):
    url = f"{api_base_url}/identity/resources/permissions/v1/{permission_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.delete(url, headers=headers)
    if response.status_code in [200, 204]:
        print(f"Deleted permission ID: {permission_id}")
    else:
        raise Exception(f"Failed to delete permission ID {permission_id}. Status: {response.status_code}, Response: {response.text}")

def delete_category(token, api_base_url, environment_id, category_id):
    url = f"{api_base_url}/identity/resources/permissions/v1/categories/{category_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.delete(url, headers=headers)
    if response.status_code in [200, 204]:
        print(f"Deleted category ID: {category_id}")
    else:
        raise Exception(f"Failed to delete category ID {category_id}. Status: {response.status_code}, Response: {response.text}")

def create_category(token, api_base_url, environment_id, name, description):
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "name": name,
        "description": description
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201]:
        category = response.json()
        print(f"Created category: {name} with ID: {category.get('id')}")
        return category
    else:
        raise Exception(f"Failed to create category {name}. Status: {response.status_code}, Response: {response.text}")

def fetch_all_categories(token, api_base_url, environment_id):
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch all categories. Status: {response.status_code}, Response: {response.text}")

def create_permission(token, api_base_url, environment_id, permission):
    url = f"{api_base_url}/identity/resources/permissions/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = [permission]  # API expects a list of permissions
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201]:
        print(f"Created permission: {permission['key']}")
    else:
        raise Exception(f"Failed to create permission {permission['key']}. Status: {response.status_code}, Response: {response.text}")

def main():
    parser = argparse.ArgumentParser(description="Set permissions and categories in a given Frontegg environment.")
    parser.add_argument("--client_id", required=True, help="Frontegg client ID")
    parser.add_argument("--secret_key", required=True, help="Frontegg secret key")
    parser.add_argument("--api_base_url", required=True, help="Frontegg API base URL")
    parser.add_argument("--environment_id", required=True, help="Target environment ID")
    parser.add_argument("--categories_json", required=True, help="JSON string with categories array")
    parser.add_argument("--permissions_json", required=True, help="JSON string with permissions array")

    args = parser.parse_args()

    try:
        # Parse the JSON strings
        categories_to_create = json.loads(args.categories_json)  # [{"name": "...", "description":"..."}, ...]
        permissions_to_create = json.loads(args.permissions_json) # [{"key":"...","name":"...","description":"...","oldCategoryName":"...","assignmentType":"..."}]

        # Authenticate and get token
        token = get_access_token(args.environment_id, args.secret_key, args.api_base_url)
        print("Authenticated successfully.")

        # Step 1: Fetch current permissions
        current_permissions = fetch_permissions(token, args.api_base_url, args.environment_id)
        print(f"Fetched {len(current_permissions)} current permissions.")

        # Step 2: Delete permissions with fePermission == false
        print(f"Identified {len(current_permissions)} permissions to delete (fePermission == false).")
        for perm in current_permissions:
            delete_permission(token, args.api_base_url, args.environment_id, perm["id"])

        # Step 3: Fetch current categories
        current_categories = fetch_categories(token, args.api_base_url, args.environment_id)
        print(f"Fetched {len(current_categories)} current categories.")

        # Step 4: Delete categories with feCategory == false
        print(f"Identified {len(current_categories)} categories to delete (feCategory == false).")
        for cat in current_categories:
            delete_category(token, args.api_base_url, args.environment_id, cat["id"])

        print("Deleted all existing categories and permissions with feCategory or fePermission == false.")

        # Step 5: Upload new categories
        print("Uploading new categories...")
        # Keep track of newly created categories
        created_categories = {}
        for cat in categories_to_create:
            cat_name = cat["name"]
            cat_desc = cat.get("description", "")
            new_cat = create_category(token, args.api_base_url, args.environment_id, cat_name, cat_desc)
            created_categories[cat_name] = new_cat["id"]
        print("Created all new categories.")

        # Step 6: Fetch all categories again to build old-to-new mapping if needed
        # If the old category names are the same as the new ones, we already have a map in created_categories.
        # If you need to map old category names to new ones differently, you can do it here.

        all_current_cats = fetch_all_categories(token, args.api_base_url, args.environment_id)
        # Build a map of category name to ID from all_current_cats
        current_cat_map = {c["name"]: c["id"] for c in all_current_cats}
        old_cat_map = {c["name"]: c["id"] for c in categories_to_create}

        old_to_new_category_map = {}
        for old_cat_name, old_cat_id in old_cat_map.items():
            new_cat_id = created_categories.get(old_cat_name) or current_cat_map.get(old_cat_name)
            if not new_cat_id:
                raise Exception(f"No new category ID found for old category '{old_cat_name}'")
            old_to_new_category_map[old_cat_id] = new_cat_id

        print(old_to_new_category_map)

        print("Fetched categories again and built old_to_new_category_map.")

        # Step 7: Upload new permissions
        print("Uploading new permissions...")
        for perm in permissions_to_create:
            perm_to_upload = {
                "key": perm["key"],
                "name": perm["name"],
                "description": perm.get("description", ""),
                "categoryId": old_to_new_category_map[perm["categoryId"]],
                "assignmentType": perm.get("assignmentType", "NEVER")
            }
            create_permission(token, args.api_base_url, args.environment_id, perm_to_upload)

        print("Uploaded all new permissions.")
        print(json.dumps({"status": "success", "environment_id": args.environment_id}))

    except Exception as e:
        # Output the error in a way Terraform can understand
        error_output = {"error": str(e)}
        print(json.dumps(error_output))
        sys.exit(1)

if __name__ == "__main__":
    main()
