terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  # Intentionally no AWS provider: this module changes only local synthetic state.
}

variable "security_baseline" {
  description = "Synthetic configuration fixture, never a production deployment."
  type = object({
    version             = string
    organization_logging = bool
    delegated_findings   = bool
    configuration_audit  = bool
    least_privilege_iam  = bool
  })
  validation {
    condition     = var.security_baseline.organization_logging && var.security_baseline.delegated_findings && var.security_baseline.configuration_audit && var.security_baseline.least_privilege_iam
    error_message = "All baseline enterprise security controls must remain enabled."
  }
}

resource "terraform_data" "enterprise_control_model" {
  input = var.security_baseline
}

output "effective_security_baseline" {
  value = terraform_data.enterprise_control_model.output
}
