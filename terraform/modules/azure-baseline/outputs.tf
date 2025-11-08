output "resource_group_name" {
  description = "Name of the created resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "ID of the created resource group"
  value       = azurerm_resource_group.main.id
}

output "resource_group_location" {
  description = "Location of the resource group"
  value       = azurerm_resource_group.main.location
}

output "vnet_id" {
  description = "ID of the created Virtual Network"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Name of the created Virtual Network"
  value       = azurerm_virtual_network.main.name
}

output "vnet_address_space" {
  description = "Address space of the Virtual Network"
  value       = azurerm_virtual_network.main.address_space
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = azurerm_subnet.public[*].id
}

output "public_subnet_names" {
  description = "Names of the public subnets"
  value       = azurerm_subnet.public[*].name
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = azurerm_subnet.private[*].id
}

output "private_subnet_names" {
  description = "Names of the private subnets"
  value       = azurerm_subnet.private[*].name
}

output "subnet_address_prefixes" {
  description = "Map of subnet names to their address prefixes"
  value = {
    for subnet in concat(azurerm_subnet.public, azurerm_subnet.private) :
    subnet.name => subnet.address_prefixes
  }
}