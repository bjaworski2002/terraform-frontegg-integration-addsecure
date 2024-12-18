terraform {
  required_providers {
    frontegg = {
      source  = "frontegg/frontegg"
      version = ">= 1.0.0"
    }
  }

  required_version = ">= 1.0.0"
}

provider "frontegg" {
  client_id       = var.client_id
  secret_key      = var.secret_key
  environment_id  = var.dev_environment_id
  api_base_url    = var.api_base_url
  portal_base_url = var.portal_base_url
}

data "external" "dev_data" {
  program = ["python3", "${path.module}/scripts/get_permissions.py"]

  query = {
    client_id      = var.client_id
    secret_key     = var.secret_key
    api_base_url   = var.api_base_url
    environment_id = var.dev_environment_id
  }
}

# Decode permissions
locals {
  all_dev_permissions = jsondecode(data.external.dev_data.result.permissions)
  filtered_dev_permissions = [
    for p in local.all_dev_permissions : p
    if p["fePermission"] == false
  ]
}

output "dev_permissions" {
  description = "Filtered permissions fetched from the dev environment (no fePermission)"
  value       = local.filtered_dev_permissions
}

locals {
  all_dev_categories = jsondecode(data.external.dev_data.result.categories)
  filtered_dev_categories = [
    for c in local.all_dev_categories : c
    if c["feCategory"] == false
  ]
}

output "dev_categories" {
  description = "Filtered categories fetched from the dev environment (feCategory == false)"
  value       = local.filtered_dev_categories
}

locals {
  target_environments = {
    "staging" = var.staging_environment_id
    "qa"      = var.qa_environment_id
    "prod"    = var.prod_environment_id
  }

  environment_secrets = {
    "staging" = var.staging_environment_secret
    "qa"      = var.qa_environment_secret
    "prod"    = var.prod_environment_secret
  }
}

resource "null_resource" "upload_permissions" {
  for_each = local.target_environments

  provisioner "local-exec" {
    command = <<-EOT
      python3 ${path.module}/scripts/set_permissions.py \
        --client_id ${var.client_id} \
        --secret_key ${local.environment_secrets[each.key]} \
        --api_base_url ${var.api_base_url} \
        --environment_id ${each.value} \
        --categories_json '${jsonencode(local.filtered_dev_categories)}' \
        --permissions_json '${jsonencode(local.filtered_dev_permissions)}'
    EOT
  }
}

