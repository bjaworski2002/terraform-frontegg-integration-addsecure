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

def find_permission_key(permissions_json, permission_id):
    for permission in permissions_json:
        if permission['id'] == permission_id:
            return permission['key']
    return None

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

def create_role(token, api_base_url, environment_id, role_data):
    """
    Create a new role with the given data (key, name, etc.).
    """
    logging.info(f"Creating role '{role_data.get('key')}'...")
    url = f"{api_base_url}/identity/resources/roles/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = [{
        "key": role_data["key"],
        "name": role_data.get("name", role_data["key"]),
        "description": role_data.get("description", ""),
        "level": role_data["level"]
    }]
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201]:
        logging.info(f"Role '{role_data.get('key')}' created successfully.")
        return response.json()
    else:
        msg = f"Failed to create role '{role_data.get('key')}': {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def update_role(token, api_base_url, environment_id, role_id, role_data):
    """
    Update an existing role (by ID).
    """
    logging.info(f"Updating role '{role_data.get('key')}' with ID '{role_id}'...")
    url = f"{api_base_url}/identity/resources/roles/v1/{role_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Typically you can PATCH or PUT. Frontegg docs might differ, but let's assume PATCH:
    payload = {
        "key": role_data["key"],
        "name": role_data.get("name", role_data["key"]),
        "description": role_data.get("description", ""),
    }
    response = requests.patch(url, json=payload, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Role '{role_data.get('key')}' updated successfully.")
    else:
        msg = f"Failed to update role '{role_data.get('key')}': {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def delete_role(token, api_base_url, environment_id, role_id, role_key):
    """
    Delete a role by ID.
    Make sure the role does not have any permissions assigned first,
    or the DELETE call might fail.
    """
    logging.info(f"Deleting role '{role_key}' (ID: {role_id})...")
    url = f"{api_base_url}/identity/resources/roles/v1/{role_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Must unassign permissions first if there's a 403 or 409 error
    response = requests.delete(url, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Role '{role_key}' deleted successfully.")
    else:
        msg = f"Failed to delete role '{role_key}': {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def update_role_permissions(token, api_base_url, environment_id, role_id, perm_ids):
    """
    PUT /roles/v1/{roleId}/permissions
    with { "permissionIds": ["..."] }
    """
    logging.info(f"Updating role permissions for role_id='{role_id}' with permissions={perm_ids}")
    url = f"{api_base_url}/identity/resources/roles/v1/{role_id}/permissions"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"permissionIds": perm_ids}
    response = requests.put(url, json=payload, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Permissions assigned successfully to role {role_id}.")
    else:
        msg = f"Failed to update role permissions for {role_id}: {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def sync_roles(token, api_base_url, environment_id, desired_roles, desired_permissions):
    """
    desired_roles: a list of roles from the dev environment
      e.g. [{ "key": "Admin", "name": "Admin", "permissions": ["perm-key-1", ...] }, ...]

    perm_map: a dict { "perm-key": "permission_id_in_target_env", ... }
      from sync_permissions so we know how to map each dev permission to the target environment ID.

    categories_json: JSON string of categories to find category names by ID

    Strategy:
      1) fetch existing roles in target
      2) match by role.key
      3) create or update
      4) sync each role’s permission IDs
      5) (optional) delete roles that don’t exist in dev
    """
    # 1) fetch existing target roles
    existing_roles_resp = requests.get(
        f"{api_base_url}/identity/resources/roles/v1",
        headers={
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    if existing_roles_resp.status_code != 200:
        raise Exception(
            f"Failed to fetch roles in target env. Status={existing_roles_resp.status_code} Body={existing_roles_resp.text}"
        )

    existing_roles = existing_roles_resp.json()  # list of role objects
    existing_roles_by_key = {r["key"]: r for r in existing_roles}
    all_existing_permissions = fetch_all_permissions(token, api_base_url, environment_id)
    existing_permissions = [p for p in all_existing_permissions]
    existing_perm_by_key = {p["key"]: p for p in existing_permissions}
    print(existing_permissions)
    logging.debug(f"existing_roles_by_key: {existing_roles_by_key}")

    # 2) create or update
    for role in desired_roles:
        dev_role_key = role["key"]
        dev_role_name = role.get("name", dev_role_key)
        dev_role_desc = role.get("description", "")
        dev_role_permissions = role.get("permissions", [])

        logging.debug(f"Processing role: {dev_role_key}")

        if dev_role_key in existing_roles_by_key:
            # update if name/description differ
            target_role = existing_roles_by_key[dev_role_key]
            role_id = target_role["id"]
            need_update = False

            if target_role.get("name") != dev_role_name or target_role.get("description") != dev_role_desc:
                update_role(token, api_base_url, environment_id, role_id, role)
                need_update = True
                logging.info(f"Role '{dev_role_key}' updated.")

        else:
            # create role
            new_role = create_role(token, api_base_url, environment_id, role)
            role_id = new_role["id"]
            existing_roles_by_key[dev_role_key] = new_role  # keep track in memory
            logging.info(f"Role '{dev_role_key}' created with ID '{role_id}'.")

        # 3) sync permissions for the role
        target_role_id = existing_roles_by_key[dev_role_key]["id"]
        target_perm_ids = []

        for dev_id in dev_role_permissions:
            key = find_permission_key(desired_permissions, dev_id)
            if key:
                env_id = existing_perm_by_key[key]["id"]
                target_perm_ids.append(env_id)
            else:
                logging.warning(f"Desired permission key '{dev_id}' not found in target environment. Skipping.")

        logging.debug(f"Permission IDs to assign to role '{dev_role_key}': {target_perm_ids}")

        # Now do the PUT roles/v1/{roleId}/permissions
        update_role_permissions(token, api_base_url, environment_id, target_role_id, target_perm_ids)

    # 4) (Optional) Delete roles in target that are not in dev
    dev_role_keys = set(r["key"] for r in desired_roles)
    for target_role_key, target_role_obj in existing_roles_by_key.items():
        if target_role_key not in dev_role_keys:
            # Potentially skip default roles or handle them carefully
            if not target_role_obj.get("isDefault", False):
                # unassign role’s permissions first (if needed)
                update_role_permissions(token, api_base_url, environment_id, target_role_obj["id"], [])
                # now delete
                delete_role(token, api_base_url, environment_id, target_role_obj["id"], target_role_key)

def fetch_all_features(token, api_base_url, environment_id):
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

            # Logging for debugging purposes
            logging.info(f"Fetched {len(items)} features. hasNext: {has_next}")

            if has_next:
                offset += limit  # Move to the next set of items
            else:
                break  # All features have been fetched
        else:
            raise Exception(f"Failed to fetch features. Status: {response.status_code}, Response: {response.text}")

    return all_features

def create_feature(token, api_base_url, environment_id, feature_data):
    logging.info(f"Creating feature '{feature_data.get('key')}'...")
    url = f"{api_base_url}/entitlements/resources/features/v1"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, json=feature_data, headers=headers)
    if response.status_code in [200, 201]:
        created_feature = response.json()
        logging.info(f"Feature '{feature_data.get('key')}' created successfully.")
        return created_feature
    else:
        msg = f"Failed to create feature '{feature_data.get('key')}': {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def update_feature(token, api_base_url, environment_id, feature_id, feature_data):
    logging.info(f"Updating feature ID '{feature_id}'...")
    url = f"{api_base_url}/entitlements/resources/features/v1/{feature_id}"
    headers = {
        "authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "name": feature_data.get("name"),
        "description": feature_data.get("description", ""),
        "permissions": feature_data.get("permissions", []),
    }
    response = requests.patch(url, json=payload, headers=headers)
    if response.status_code in [200, 204]:
        logging.info(f"Feature ID '{feature_id}' updated successfully.")
    else:
        msg = f"Failed to update feature '{feature_data.get('key')}': {response.status_code} {response.text}"
        logging.error(msg)
        raise Exception(msg)

def delete_feature(token, api_base_url, environment_id, feature_id, feature_key):
    # If you actually want to delete:
    # url = f"{api_base_url}/entitlements/resources/features/v1/{feature_id}"
    # headers = {
    #     "authorization": f"Bearer {token}",
    #     "Content-Type": "application/json",
    # }
    # response = requests.delete(url, headers=headers)
    # ...
    logging.info(f"[SKIP] Delete feature '{feature_key}' (ID: {feature_id}') would go here.")

def sync_features(token, api_base_url, environment_id, desired_features):
    logging.info("Synchronizing features...")
    existing_features = fetch_all_features(token, api_base_url, environment_id)
    existing_by_key = {f["key"]: f for f in existing_features}

    # Create or update
    for desired in desired_features:
        dev_key = desired["key"]
        if dev_key in existing_by_key:
            target_feat = existing_by_key[dev_key]
            feat_id = target_feat["id"]

            # Check if anything changed
            if (
                target_feat.get("name") != desired.get("name") or
                target_feat.get("description", "") != desired.get("description", "") or
                set(target_feat.get("permissions", [])) != set(desired.get("permissions", []))
            ):
                update_feature(token, api_base_url, environment_id, feat_id, desired)
        else:
            # Create new
            create_feature(token, api_base_url, environment_id, desired)

    # (Optional) Delete any features not in desired
    dev_feature_keys = set(f["key"] for f in desired_features)
    for key, feat_obj in existing_by_key.items():
        if key not in dev_feature_keys:
            logging.info(f"Feature '{key}' not in dev. Consider deletion.")
            # delete_feature(token, api_base_url, environment_id, feat_obj["id"], key)

    logging.info("Features synchronized.")

def main():
    parser = argparse.ArgumentParser(
        description="Sync permissions, categories, and roles in a given Frontegg environment.")
    parser.add_argument("--client_id", required=True, help="Frontegg client ID")
    parser.add_argument("--secret_key", required=True, help="Frontegg secret key")
    parser.add_argument("--api_base_url", required=True, help="Frontegg API base URL")
    parser.add_argument("--environment_id", required=True, help="Target environment ID")
    parser.add_argument("--categories_json", required=True, help="JSON string with categories array")
    parser.add_argument("--permissions_json", required=True, help="JSON string with permissions array")
    parser.add_argument("--roles_json", required=True, help="JSON string with roles array")
    parser.add_argument("--features_json", required=True, help="JSON string with features array")

    args = parser.parse_args()

    try:
        logging.info("Starting synchronization script...")

        # Parse JSON inputs
        desired_categories = json.loads(args.categories_json)
        desired_permissions = json.loads(args.permissions_json)
        desired_roles = json.loads(args.roles_json) if args.roles_json else []
        desired_features = json.loads(args.features_json) if args.features_json else []

        logging.info(
            f"Parsed {len(desired_categories)} categories, {len(desired_permissions)} permissions, and {len(desired_roles)} roles.")

        # Authenticate and get token
        token = get_access_token(args.client_id, args.secret_key, args.api_base_url)

        # 1. Sync categories: create/update (no deletion)
        logging.info("Synchronizing categories...")
        cat_map = sync_categories(token, args.api_base_url, args.environment_id, desired_categories)

        # 2. Sync permissions: create/update (no deletion)
        logging.info("Synchronizing permissions...")
        sync_permissions(
            token,
            args.api_base_url,
            args.environment_id,
            desired_permissions,
            cat_map,
            args.categories_json
        )

        # 3. Sync roles: create/update/delete
        logging.info("Synchronizing roles...")
        sync_roles(
            token,
            args.api_base_url,
            args.environment_id,
            desired_roles,
            desired_permissions,
        )

        sync_features(token, args.api_base_url, args.environment_id, desired_features)

        # Final output for Terraform
        logging.info("Synchronization complete. Sending success status to Terraform.")
        print(json.dumps({"status": "success", "environment_id": args.environment_id}))

    except Exception as e:
        # Log the full stack trace
        logging.exception("Error during synchronization")

        # Output the error in a way Terraform can understand
        error_output = {"error": str(e)}
        print(json.dumps(error_output), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
