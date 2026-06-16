## ClinicSentry — GCP reference deployment.
##
## Provisions: VPC, Cloud SQL Postgres, GCS bucket with retention, Cloud KMS
## key, IAM service account, log-based alert on chain-verification failure.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" { type = string }
variable "region"     { type = string; default = "us-central1" }
variable "name_prefix" { type = string; default = "clinicsentry" }
variable "archive_retention_days" { type = number; default = 2555 }

resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "default" {
  name          = "${var.name_prefix}-subnet"
  ip_cidr_range = "10.42.0.0/20"
  network       = google_compute_network.vpc.id
  region        = var.region
  private_ip_google_access = true
}

resource "google_kms_key_ring" "main" {
  name     = "${var.name_prefix}-kr"
  location = var.region
}

resource "google_kms_crypto_key" "audit" {
  name            = "audit"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days
}

resource "google_sql_database_instance" "audit" {
  name             = "${var.name_prefix}-audit"
  region           = var.region
  database_version = "POSTGRES_16"
  settings {
    tier = "db-custom-2-7680"
    backup_configuration { enabled = true }
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
  }
  deletion_protection = true
}

resource "google_sql_database" "main" {
  name     = "clinicsentry"
  instance = google_sql_database_instance.audit.name
}

resource "google_storage_bucket" "archive" {
  name          = "${var.name_prefix}-archive-${var.project_id}"
  location      = var.region
  storage_class = "STANDARD"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  retention_policy {
    is_locked        = false
    retention_period = var.archive_retention_days * 86400
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.audit.id
  }

  versioning { enabled = true }
}

resource "google_service_account" "service" {
  account_id   = "${var.name_prefix}-svc"
  display_name = "ClinicSentry service account"
}

resource "google_storage_bucket_iam_member" "writer" {
  bucket = google_storage_bucket.archive.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.service.email}"
}

resource "google_kms_crypto_key_iam_member" "kms" {
  crypto_key_id = google_kms_crypto_key.audit.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.service.email}"
}

output "sql_instance_connection_name" {
  value = google_sql_database_instance.audit.connection_name
}

output "archive_bucket" {
  value = google_storage_bucket.archive.name
}

output "service_account_email" {
  value = google_service_account.service.email
}
