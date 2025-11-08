# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project_name}-${var.environment}"
  location = var.location

  tags = var.tags
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.project_name}"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = var.tags
}

# Public Subnets
resource "azurerm_subnet" "public" {
  count                = length(var.public_subnet_cidrs)
  name                 = "snet-${var.project_name}-public-${count.index + 1}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.public_subnet_cidrs[count.index]]

  # Enable for Application Gateway if needed
  # service_endpoints = ["Microsoft.Web", "Microsoft.Sql"]
}

# Private Subnets
resource "azurerm_subnet" "private" {
  count                = length(var.private_subnet_cidrs)
  name                 = "snet-${var.project_name}-private-${count.index + 1}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.private_subnet_cidrs[count.index]]

  # Enable service endpoints for private resources
  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]
}

# Network Security Group for public subnets
resource "azurerm_network_security_group" "public" {
  name                = "nsg-${var.project_name}-public"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = var.tags
}

# Network Security Group for private subnets
resource "azurerm_network_security_group" "private" {
  name                = "nsg-${var.project_name}-private"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "DenyInternet"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  tags = var.tags
}

# Associate NSG with subnets
resource "azurerm_subnet_network_security_group_association" "public" {
  count                     = length(azurerm_subnet.public)
  subnet_id                 = azurerm_subnet.public[count.index].id
  network_security_group_id = azurerm_network_security_group.public.id
}

resource "azurerm_subnet_network_security_group_association" "private" {
  count                     = length(azurerm_subnet.private)
  subnet_id                 = azurerm_subnet.private[count.index].id
  network_security_group_id = azurerm_network_security_group.private.id
}

# Route Table for private subnets
resource "azurerm_route_table" "private" {
  name                = "rt-${var.project_name}-private"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Route to blackhole internet traffic (enhanced security)
  route {
    name           = "BlackholeInternet"
    address_prefix = "0.0.0.0/0"
    next_hop_type  = "None"
  }

  tags = var.tags
}

# Associate route table with private subnets
resource "azurerm_subnet_route_table_association" "private" {
  count          = length(azurerm_subnet.private)
  subnet_id      = azurerm_subnet.private[count.index].id
  route_table_id = azurerm_route_table.private.id
}