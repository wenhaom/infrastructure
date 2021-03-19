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
  # egress {
  #   from_port   = 0
  #   to_port     = 0
  #   protocol    = "-1"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
}

resource "aws_s3_bucket" "webapp-wenhao-min" {
  bucket = "webapp-wenhao-min"
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
resource "aws_db_subnet_group" "subnetforrdsinstances" {
  name       = "subnetforrdsinstances"
  subnet_ids = [aws_subnet.subnet1.id, aws_subnet.subnet2.id, aws_subnet.subnet3.id]

  tags = {
    Name = "subnetforrdsinstances"
  }
}

resource "aws_db_instance" "csye6225" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  identifier           = "csye6225"
  name                 = "csye6225"
  username             = "csye6225"
  password             = "Mmwh1992"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  multi_az             = "false"
  db_subnet_group_name = aws_db_subnet_group.subnetforrdsinstances.id

  publicly_accessible    = "false"
  vpc_security_group_ids = [aws_security_group.database.id]
  apply_immediately      = true
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
          "arn:aws:s3:::webapp-wenhao-min",
          "arn:aws:s3:::webapp-wenhao-min/*"
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
  tags = {
    tag-key = "tag-value"
  }
}
resource "aws_iam_policy_attachment" "test-attach" {
  name       = "test-attachment"
  roles      = [aws_iam_role.EC2-CSYE6225.name]
  policy_arn = aws_iam_policy.WebAppS3.arn
}


resource "aws_iam_instance_profile" "profile" {
  name = "profile"
  role = aws_iam_role.EC2-CSYE6225.name
}
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["839935233432"]
}

# resource "aws_instance" "web" {
#   ami           = data.aws_ami.ubuntu.id
#   instance_type = "t2.micro"
#   tags = {
#     Name = "myfirstInstance"
#   }
#   disable_api_termination = false
#   root_block_device {
#     volume_size = 20
#     volume_type = "gp2"
#   }
#   network_interface {
#     network_interface_id = aws_network_interface.foo.id
#     device_index         = 0
#   }
#   iam_instance_profile = aws_iam_instance_profile.profile.name
#   key_name             = "6225"
#   depends_on           = [aws_db_instance.csye6225]
#   user_data            = <<EOF
# #!/bin/bash
# sudo touch .env
# sudo echo '#!/bin/bash' > .env
# sudo echo "HOST="${aws_db_instance.csye6225.address}."
# USERNAME="${aws_db_instance.csye6225.username}"
# PASSWORD="${aws_db_instance.csye6225.password}"
# Bucket="${aws_s3_bucket.webapp-wenhao-min.id}"
# DB="${aws_db_instance.csye6225.name}"" >> .env
# cd  /var/lib/cloud/instance/scripts/
# sudo ./part-001
# EOF
# }

resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  path        = "/"
  description = "allows EC2 instances to read data from S3 buckets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::codedeploy.wenhao.min.prod",
          "arn:aws:s3:::codedeploy.wenhao.min.prod/*"
        ]
      },
    ]
  })
}

resource "aws_iam_policy" "GH-Upload-To-S3" {
  name        = "GH-Upload-To-S3"
  path        = "/"
  description = "allows GitHub Actions to upload artifacts from latest successful build to dedicated S3 bucket used by CodeDeploy."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject",
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" : [
          "arn:aws:s3:::ghactions"
        ]
      },
    ]
  })
}
resource "aws_iam_policy" "GH-Code-Deploy" {
  name        = "GH-Code-Deploy"
  path        = "/"
  description = "allows GitHub Actions to call CodeDeploy APIs to initiate application deployment on EC2 instances."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Action" : [
          "codedeploy:RegisterApplicationRevision",
          "codedeploy:GetApplicationRevision"
        ],
        "Resource" : [
          "arn:aws:codedeploy:us-east-1:231232113671:application:csye6225-webapp"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "codedeploy:CreateDeployment",
          "codedeploy:GetDeployment"
        ],
        "Resource" : [
          "*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "codedeploy:GetDeploymentConfig"
        ],
        "Resource" : [
          "arn:aws:codedeploy:us-east-1:231232113671:deploymentconfig:CodeDeployDefault.OneAtATime",
          "arn:aws:codedeploy:us-east-1:231232113671:deploymentconfig:CodeDeployDefault.HalfAtATime",
          "arn:aws:codedeploy:us-east-1:231232113671:deploymentconfig:CodeDeployDefault.AllAtOnce"
        ]
      }
    ]
  })
}
//change CODE_DEPLOY_APPLICATION_NAME

resource "aws_iam_policy" "policy" {
  name        = "gh-ec2-ami"
  path        = "/"
  description = "provides the minimal set permissions necessary for Packer to work:"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:CreateLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:CreateFleet",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeVpcs"
        ],
        "Resource" : "*"
      }
    ]
  })
}


resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
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
  tags = {
    tag-key = "tag-value"
  }
}
resource "aws_iam_policy_attachment" "ec2service-attach" {
  name       = "ec2service-attachment"
  roles      = [aws_iam_role.CodeDeployEC2ServiceRole.name]
  policy_arn = aws_iam_policy.CodeDeploy-EC2-S3.arn
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "",
        "Effect" : "Allow",
        "Principal" : {
          "Service" : [
            "codedeploy.amazonaws.com"
          ]
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_policy_attachment" "codedeployservicerole-attach" {
  name       = "codedeployservicerole-attachment"
  roles      = [aws_iam_role.CodeDeployServiceRole.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}
resource "aws_iam_policy_attachment" "CodeDeployEC2ServiceRole-attachS3" {
  name       = "CodeDeployEC2ServiceRole-attachS3"
  roles      = [aws_iam_role.CodeDeployEC2ServiceRole.name]
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_instance_profile" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}
resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  tags = {
    Name = "CodeDeployEC2"
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
  iam_instance_profile = aws_iam_instance_profile.CodeDeployEC2ServiceRole.name
  key_name             = "6225"
  depends_on           = [aws_db_instance.csye6225]
  user_data            = <<EOF
#!/bin/bash
sudo touch .env
sudo echo '#!/bin/bash' > .env
sudo echo "HOST="${aws_db_instance.csye6225.address}."
USERNAME="${aws_db_instance.csye6225.username}"
PASSWORD="${aws_db_instance.csye6225.password}"
Bucket="${aws_s3_bucket.webapp-wenhao-min.id}"
DB="${aws_db_instance.csye6225.name}"" >> /etc/environment
EOF
}


resource "aws_codedeploy_app" "example" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "example" {
  app_name               = "csye6225-webapp"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  deployment_group_name  = "csye6225-webapp-deployment"
  service_role_arn       = aws_iam_role.CodeDeployServiceRole.arn

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "CodeDeployEC2"
    }
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}




















