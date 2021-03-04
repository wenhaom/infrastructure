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


resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow application inbound traffic"
  vpc_id      = aws_vpc.vpc1234.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "application"
  }
}


resource "aws_network_interface" "foo" {
  subnet_id       = aws_subnet.subnet1.id
  security_groups = [aws_security_group.application.id]
  tags = {
    Name = "primary_network_interface"
  }
}

resource "aws_security_group" "database" {
  name   = "database"
  vpc_id = aws_vpc.vpc1234.id
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }




}

resource "aws_s3_bucket" "bucket" {
  bucket = "webapp.wenhao.min"
  acl    = "private"

  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        //kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }

}
resource "aws_db_subnet_group" "subnet-for-rds-instances" {
  name       = "subnet-for-rds-instances"
  subnet_ids = [aws_subnet.subnet1.id, aws_subnet.subnet2.id, aws_subnet.subnet3.id]

  tags = {
    Name = "My DB subnet group"
  }
}


resource "aws_db_instance" "csye6225" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  name                   = "csye6225"
  username               = "csye6225"
  password               = "Mmwh1992"
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  multi_az               = "false"
  db_subnet_group_name   = "subnet-for-rds-instances"
  identifier             = "csye6225"
  publicly_accessible    = "false"
  vpc_security_group_ids = [aws_security_group.database.id]
}

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  path        = "/"
  description = "My WebAppS3 policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:*"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::YOUR_BUCKET_NAME",
          "arn:aws:s3:::YOUR_BUCKET_NAME/bucket"
        ]
      }
    ]
  })
}
resource "aws_iam_role" "EC2-CSYE6225" {
  name = "EC2-CSYE6225"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  inline_policy {
    name   = "WebAppS3"
    policy = aws_iam_policy.WebAppS3.policy
  }

  tags = {
    tag-key = "tag-value"
  }
}
resource "aws_iam_instance_profile" "profile" {
  name = "profile"
  role = aws_iam_role.EC2-CSYE6225.name
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["839935233432"]
}


resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  tags = {
    Name = "myfirstInstance"
  }
  disable_api_termination = false
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }


  network_interface {
    network_interface_id = aws_network_interface.foo.id
    device_index         = 0
  }
  //security_groups = [aws_security_group.application.name]

  iam_instance_profile = aws_iam_instance_profile.profile.name
  key_name             = "6225"

}













