# For production, use remote state storage
# Uncomment and configure when ready for team use

# terraform {
#   backend "s3" {
#     bucket = "cloudguardstack-tfstate-prod"
#     key    = "production/terraform.tfstate"
#     region = "us-east-1"
#     encrypt = true
#   }
# }

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}