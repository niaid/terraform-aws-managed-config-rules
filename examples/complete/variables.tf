variable "acm_certificate_expiration_check" {
  description = "Time in days before alerting that your ACM cert will expire"
  default     = 30
  type        = number
}