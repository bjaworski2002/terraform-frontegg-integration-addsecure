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

locals {
  all_dev_permissions = jsondecode(data.external.dev_data.result.permissions)
}

output "dev_permissions" {
  description = "Filtered permissions fetched from the dev environment"
  value       = local.all_dev_permissions
}

locals {
  all_dev_categories = jsondecode(data.external.dev_data.result.categories)
}

output "dev_categories" {
  description = "Filtered categories fetched from the dev environment"
  value       = local.all_dev_categories
}

locals {
  all_dev_roles = jsondecode(data.external.dev_data.result.roles)
}

output "dev_roles" {
  description = "Filtered roles from dev environment"
  value       = local.all_dev_roles
}

locals {
  all_dev_features = jsondecode(data.external.dev_data.result.features)
}

output "dev_features" {
  description = "Filtered features from dev environment"
  value       = local.all_dev_features
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
        --client_id ${local.target_environments[each.key]} \
        --secret_key ${local.environment_secrets[each.key]} \
        --api_base_url ${var.api_base_url} \
        --environment_id ${each.value} \
        --categories_json '${jsonencode(local.all_dev_categories)}' \
        --permissions_json '${jsonencode(local.all_dev_permissions)}' \
        --roles_json '${jsonencode(local.all_dev_roles)}' \
        --features_json '${jsonencode(local.all_dev_features)}'
    EOT
  }
}

