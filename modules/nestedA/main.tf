provider "aws" {
  region = var.region
}
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}
variable "subnet_cidr_block" {
  type    = string
  default = "10.0.1.0/24"
}
resource "aws_vpc" "vpc1234" {
  cidr_block                       = var.cidr_block
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "csye6225-vpc-spring2021"
  }
}
resource "aws_subnet" "subnet1" {
  vpc_id                  = aws_vpc.vpc1234.id
  cidr_block              = var.subnet_cidr_block
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-subnet01"
  }
}
resource "aws_subnet" "subnet2" {
  vpc_id                  = aws_vpc.vpc1234.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-subnet02"
  }
}
resource "aws_subnet" "subnet3" {
  vpc_id                  = aws_vpc.vpc1234.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = true
  tags = {
    Name = "csye6225-subnet03"
  }
}
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc1234.id

  tags = {
    Name = "gateway"
  }
}
resource "aws_route_table" "r" {
  vpc_id = aws_vpc.vpc1234.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "route"
  }
}
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.r.id
}
resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.r.id
}
resource "aws_route_table_association" "c" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.r.id
}
