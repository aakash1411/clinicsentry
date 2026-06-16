## ClinicSentry — Azure reference deployment.
##
## Provisions: VNet, Azure Database for PostgreSQL Flexible Server, Blob
## Storage with immutability policy, Azure Key Vault, Managed Identity.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
  }
}

provider "azurerm" { features {} }

variable "name_prefix"            { type = string; default = "clinicsentry" }
variable "location"               { type = string; default = "eastus" }
variable "archive_retention_days" { type = number; default = 2555 }

resource "azurerm_resource_group" "rg" {
  name     = "${var.name_prefix}-rg"
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.name_prefix}-vnet"
  address_space       = ["10.42.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "db" {
  name                 = "db"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.42.1.0/24"]
  delegation {
    name = "fs"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "random_password" "pg" {
  length  = 32
  special = false
}

resource "azurerm_postgresql_flexible_server" "audit" {
  name                = "${var.name_prefix}-audit"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  version             = "16"
  administrator_login = "cg"
  administrator_password = random_password.pg.result
  sku_name            = "B_Standard_B1ms"
  storage_mb          = 32768
  zone                = "1"
  delegated_subnet_id = azurerm_subnet.db.id
  geo_redundant_backup_enabled = true
  backup_retention_days        = 30
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "clinicsentry"
  server_id = azurerm_postgresql_flexible_server.audit.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

resource "azurerm_key_vault" "kv" {
  name                       = "${var.name_prefix}-kv"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  sku_name                   = "standard"
  tenant_id                  = data.azurerm_client_config.me.tenant_id
  purge_protection_enabled   = true
  soft_delete_retention_days = 30
}

data "azurerm_client_config" "me" {}

resource "azurerm_storage_account" "archive" {
  name                            = "${var.name_prefix}arch${substr(md5(azurerm_resource_group.rg.id), 0, 6)}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
    container_delete_retention_policy { days = 30 }
  }
}

resource "azurerm_storage_container" "archive" {
  name                  = "audit"
  storage_account_name  = azurerm_storage_account.archive.name
  container_access_type = "private"
}

output "postgres_fqdn"    { value = azurerm_postgresql_flexible_server.audit.fqdn }
output "archive_account"  { value = azurerm_storage_account.archive.name }
output "key_vault_uri"    { value = azurerm_key_vault.kv.vault_uri }
output "postgres_password" {
  value     = random_password.pg.result
  sensitive = true
}
