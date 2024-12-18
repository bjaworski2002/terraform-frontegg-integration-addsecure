variable "client_id" {
  description = "The Client ID for Frontegg API"
  type        = string
}

variable "secret_key" {
  description = "The Secret Key for Frontegg API"
  type        = string
  sensitive   = true
}

variable "dev_environment_id" {
  description = "The Dev Environment ID for Frontegg"
  type        = string
}

variable "staging_environment_id" {
  description = "The Staging Environment ID for Frontegg"
  type        = string
}

variable "qa_environment_id" {
  description = "The QA Environment ID for Frontegg"
  type        = string
}

variable "prod_environment_id" {
  description = "The Prod Environment ID for Frontegg"
  type        = string
}

variable "staging_environment_secret" {
  description = "The Staging Environment Secret for Frontegg"
  type        = string
}

variable "qa_environment_secret" {
  description = "The QA Environment Secret for Frontegg"
  type        = string
}

variable "prod_environment_secret" {
  description = "The Prod Environment Secret for Frontegg"
  type        = string
}

variable "api_base_url" {
  description = "API base URL"
  type        = string
  default     = "https://api.frontegg.com"
}

variable "portal_base_url" {
  description = "Portal base URL"
  type        = string
  default     = "https://frontegg-portal.frontegg.com"
}
