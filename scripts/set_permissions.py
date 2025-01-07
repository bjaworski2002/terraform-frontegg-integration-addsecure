#!/usr/bin/env python3

import sys
import json
import requests
import argparse
import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Set to DEBUG for more detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)


def get_access_token(client_id, secret_key, api_base_url):
    """
    Use your environment's clientId + secret to get an access token from Frontegg.
    """
    logging.info("Fetching access token...")
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
            logging.error("Token not found in the response.")
            raise Exception("Token not found in the response.")
        logging.info("Access token fetched successfully.")
        return token
    else:
        logging.error(f"Failed to fetch token. Status: {response.status_code}, Response: {response.text}")
        raise Exception(f"Failed to fetch token. Status: {response.status_code}, Response: {response.text}")


def fetch_all_categories(token, api_base_url, environment_id):
    """
    Return all categories in the environment.
    """
    logging.info("Fetching all categories...")
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        logging.info("Fetched categories successfully.")
        return response.json()  # list of categories
    else:
        logging.error(f"Failed to fetch categories. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to fetch categories. Status: {response.status_code}, Response: {response.text}"
        )


def fetch_all_permissions(token, api_base_url, environment_id):
    """
    Return all permissions in the environment.
    """
    logging.info("Fetching all permissions...")
    url = f"{api_base_url}/identity/resources/permissions/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        logging.info("Fetched permissions successfully.")
        return response.json()  # list of permissions
    else:
        logging.error(f"Failed to fetch permissions. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to fetch permissions. Status: {response.status_code}, Response: {response.text}"
        )


def create_category(token, api_base_url, environment_id, name, description):
    """
    Create a new category with the given name and description.
    """
    logging.info(f"Creating category '{name}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1/categories"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "name": name,
        "description": description or ""
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201]:
        logging.info(f"Category '{name}' created successfully.")
        return response.json()  # returns the newly-created category
    else:
        logging.error(f"Failed to create category '{name}'. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to create category '{name}'. Status: {response.status_code}, Response: {response.text}"
        )


def update_category(token, api_base_url, environment_id, category_id, name, description):
    """
    Update an existing category (by ID).
    """
    logging.info(f"Updating category ID '{category_id}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1/categories/{category_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json",
    }
    payload = {
        "name": name,
        "description": description or ""
    }
    response = requests.patch(url, json=payload, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Category ID '{category_id}' updated successfully.")
        return
    else:
        logging.error(f"Failed to update category ID '{category_id}'. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to update category ID '{category_id}'. Status: {response.status_code}, Response: {response.text}"
        )


def delete_category(token, api_base_url, environment_id, category_id):
    """
    Delete a category by ID.
    """
    logging.info(f"Attempting to delete category ID '{category_id}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1/categories/{category_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "frontegg-tenant-id": environment_id,
        "Content-Type": "application/json",
    }
    response = requests.delete(url, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Category ID '{category_id}' deleted successfully.")
    else:
        error_message = f"Failed to delete category ID '{category_id}'. Status: {response.status_code}, Response: {response.text}"
        logging.error(error_message)
        raise Exception(error_message)


def create_permission(token, api_base_url, environment_id, permission):
    """
    Create a new permission. Frontegg expects a list of permissions in the POST body,
    but we can send them as a single-element list.
    """
    logging.info(f"Creating permission '{permission.get('key')}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = [permission]
    logging.info(payload)
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201]:
        logging.info(f"Permission '{permission.get('key')}' created successfully.")
    else:
        logging.error(f"Failed to create permission '{permission.get('key')}'. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to create permission '{permission.get('key')}'. Status: {response.status_code}, Response: {response.text}"
        )


def update_permission(token, api_base_url, environment_id, permission_id, permission_update):
    """
    Update an existing permission (by ID).
    """
    logging.info(f"Updating permission ID '{permission_id}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1/{permission_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.patch(url, json=permission_update, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Permission ID '{permission_id}' updated successfully.")
    else:
        logging.error(f"Failed to update permission ID '{permission_id}'. Status: {response.status_code}, Response: {response.text}")
        raise Exception(
            f"Failed to update permission ID '{permission_id}'. Status: {response.status_code}, Response: {response.text}"
        )


def delete_permission(token, api_base_url, environment_id, permission_id, perm_key):
    """
    Delete a permission by ID.
    """
    logging.info(f"Attempting to delete permission Key '{perm_key}'...")
    url = f"{api_base_url}/identity/resources/permissions/v1/{permission_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.delete(url, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Permission ID '{permission_id}' deleted successfully.")
    else:
        error_message = f"Failed to delete permission ID '{permission_id}'. Status: {response.status_code}, Response: {response.text}"
        logging.error(error_message)
        raise Exception(error_message)


def sync_categories(token, api_base_url, environment_id, desired_categories):
    """
    Synchronize categories:
      - Create new ones that don't exist (by 'name')
      - Update existing ones if name matches but description changed
      - Do NOT delete existing ones that are not in desired_categories to avoid forbidden operations
    """
    logging.info("Synchronizing categories...")
    existing_categories = fetch_all_categories(token, api_base_url, environment_id)
    # Build a dict keyed by "name" from existing categories
    existing_cat_by_name = {cat["name"]: cat for cat in existing_categories}

    # Also build a dict by name from the desired categories
    # Expected structure of desired_categories: [{"name": "...", "description":"..."}, ...]
    desired_cat_by_name = {c["name"]: c for c in desired_categories}

    # 1. Create or Update
    for cat in desired_categories:
        cat_name = cat["name"]
        cat_desc = cat.get("description", "")

        if cat_name in existing_cat_by_name:
            # Check if we need to update
            existing_id = existing_cat_by_name[cat_name]["id"]
            existing_desc = existing_cat_by_name[cat_name].get("description", "")
            # If descriptions differ, update
            if cat_desc != existing_desc:
                update_category(token, api_base_url, environment_id, existing_id, cat_name, cat_desc)
        else:
            # Create a new category
            new_cat = create_category(token, api_base_url, environment_id, cat_name, cat_desc)
            # Add it to existing_cat_by_name so we know its ID
            existing_cat_by_name[cat_name] = new_cat

    # 2. (Optional) Skipping Deletion
    # If deletion is not permitted or desired, skip this step
    # for existing_cat in existing_categories:
    #     existing_name = existing_cat["name"]
    #     if existing_name not in desired_cat_by_name:
    #         delete_category(token, api_base_url, environment_id, existing_cat["id"])

    logging.info("Categories synchronized.")
    # Re-fetch or build a fresh map so that subsequent steps know the new IDs
    updated_categories = fetch_all_categories(token, api_base_url, environment_id)
    return {c["name"]: c for c in updated_categories}

def find_category_name(categories_json, category_id):
    """
    Find the category name by searching for the object in categories_json
    where the 'id' matches the given 'category_id'.

    Args:
        categories_json (list): List of category objects.
        category_id (str): The ID of the category to find.

    Returns:
        str: The name of the category if found, otherwise None.
    """
    categories_object = json.loads(categories_json)
    for category in categories_object:
        if category['id'] == category_id:
            return category['name']
    return None  # Return None if the category is not found

def sync_permissions(token, api_base_url, environment_id, desired_permissions, cat_map, categories_json):
    logging.info("Synchronizing permissions...")
    existing_permissions = fetch_all_permissions(token, api_base_url, environment_id)
    existing_perm_by_key = {p["key"]: p for p in existing_permissions}

    desired_perm_by_key = {p["key"]: p for p in desired_permissions}
    desired_perm_keys = set(p["key"] for p in desired_permissions)

    permissions_to_delete = [p for p in existing_permissions if p["key"] not in desired_perm_keys and p['fePermission'] == False]

    for perm in desired_permissions:
        perm_key = perm["key"]
        category_id = perm.get("categoryId")
        cat_name = find_category_name(categories_json, category_id)

        if not cat_name:
            logging.warning(f"Permission {perm_key} has no categoryName. Skipping category assignment.")
            category_id = None
        else:
            # Look up the category in cat_map
            if cat_name not in cat_map:
                logging.error(f"Category '{cat_name}' not found in cat_map. Check if it was created.")
                raise Exception(f"Category '{cat_name}' not found in target environment.")
            category_id = cat_map[cat_name]["id"]

        # Prepare the data for creation or update
        assignment_type = perm.get("assignmentType", "NEVER")
        new_perm_payload = {
            "key": perm_key,
            "name": perm.get("name", ""),
            "description": perm.get("description", ""),
            "categoryId": category_id,
            "assignmentType": assignment_type
        }

        # Determine if this permission already exists
        if perm_key in existing_perm_by_key:
            existing = existing_perm_by_key[perm_key]
            existing_id = existing["id"]

            # Build an update payload of changed fields
            to_update = {}
            if existing.get("name") != new_perm_payload["name"]:
                to_update["name"] = new_perm_payload["name"]
            if existing.get("description") != new_perm_payload["description"]:
                to_update["description"] = new_perm_payload["description"]
            if existing.get("categoryId") != new_perm_payload["categoryId"]:
                to_update["categoryId"] = new_perm_payload["categoryId"]
            if existing.get("assignmentType") != new_perm_payload["assignmentType"]:
                to_update["assignmentType"] = new_perm_payload["assignmentType"]

            # If something changed, patch it
            if to_update:
                update_permission(token, api_base_url, environment_id, existing_id, to_update)
        else:
            # Create new permission
            create_permission(token, api_base_url, environment_id, new_perm_payload)

    for perm in permissions_to_delete:
        perm_id = perm['id']
        perm_key = perm['key']
        try:
            delete_permission(token, api_base_url, environment_id, perm_id, perm_key)
            logging.info(f"Deleted permission '{perm_key}' with ID '{perm_id}'.")
        except Exception as e:
            if "forbidden route for tenants" in str(e).lower():
                logging.warning(f"Forbidden: Cannot delete permission '{perm_key}' with ID '{perm_id}'. Skipping.")
            else:
                logging.error(f"Failed to delete permission '{perm_key}' with ID '{perm_id}': {e}")
                continue  # Continue with next permission

    logging.info("Permissions synchronized.")


def main():
    parser = argparse.ArgumentParser(description="Sync permissions and categories in a given Frontegg environment.")
    parser.add_argument("--client_id", required=True, help="Frontegg client ID")
    parser.add_argument("--secret_key", required=True, help="Frontegg secret key")
    parser.add_argument("--api_base_url", required=True, help="Frontegg API base URL")
    parser.add_argument("--environment_id", required=True, help="Target environment ID")
    parser.add_argument("--categories_json", required=True, help="JSON string with categories array")
    parser.add_argument("--permissions_json", required=True, help="JSON string with permissions array")

    args = parser.parse_args()

    try:
        logging.info("Starting synchronization script...")
        # Parse JSON inputs
        desired_categories = json.loads(args.categories_json)
        desired_permissions = json.loads(args.permissions_json)
        logging.info(f"Parsed {len(desired_categories)} categories and {len(desired_permissions)} permissions.")

        # Authenticate and get token
        token = get_access_token(args.client_id, args.secret_key, args.api_base_url)

        # 1. Sync categories: create/update (no deletion)
        logging.info("Synchronizing categories...")
        cat_map = sync_categories(token, args.api_base_url, args.environment_id, desired_categories)

        # 2. Sync permissions: create/update (no deletion)
        logging.info("Synchronizing permissions...")
        sync_permissions(token, args.api_base_url, args.environment_id, desired_permissions, cat_map, args.categories_json)

        # Final output for Terraform
        logging.info("Synchronization complete. Sending success status to Terraform.")
        print(json.dumps({"status": "success", "environment_id": args.environment_id}))

    except Exception as e:
        # Output the error in a way Terraform can understand
        error_output = {"error": str(e)}
        print(json.dumps(error_output), file=sys.stderr)
        logging.error(f"Error during synchronization: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
