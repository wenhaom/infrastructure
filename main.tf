provider "aws" {
  region                  = var.region
  shared_credentials_file = "~/.aws/credentials"
  profile                 = var.profile
}
variable "profile" {
  type    = string
  default = "prod"
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
resource "aws_security_group" "load_balancer" {
  name        = "security-group-lb"
  description = "only allow 80 for ingress"
  vpc_id      = aws_vpc.vpc1234.id
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
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
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
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    # cidr_blocks     = ["0.0.0.0/0"]
    security_groups = [aws_security_group.load_balancer.id]
  }
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    # cidr_blocks     = ["0.0.0.0/0"]
    security_groups = [aws_security_group.load_balancer.id]
  }
  ingress {
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
    # cidr_blocks     = ["0.0.0.0/0"]
    security_groups = [aws_security_group.load_balancer.id]
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
  instance_class       = "db.t2.micro"
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
resource "aws_iam_policy_attachment" "CodeDeployEC2ServiceRole-attachCloudWatch" {
  name       = "CodeDeployEC2ServiceRole-attachCloudWatch"
  roles      = [aws_iam_role.CodeDeployEC2ServiceRole.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_instance_profile" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}
resource "aws_iam_role" "lambda_basic_execution_role" {
  name = "lambda_basic_execution_role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}
resource "aws_iam_policy" "lambda_policy" {
  name = "lambda_policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "dynamodb:*",
          "ses:*",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : "*"
      }
    ]
  })
}
resource "aws_iam_policy" "ssn-publish-message-policy" {
  name        = "policy_sns_publish_message"
  description = "allow to publish message in sns"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Action": [
              "sns:Publish"
          ],
          "Resource": [
              "arn:aws:sns:us-east-1:231232113671:topic"
          ]
      }
  ]
}
EOF
}
resource "aws_iam_policy_attachment" "attach_sns_publish_policy_to_ec2_role" {
  name       = "attach_sns_publish_policy_to_ec2_role"
  roles      = [aws_iam_role.CodeDeployEC2ServiceRole.name]
  policy_arn = aws_iam_policy.ssn-publish-message-policy.arn
}
resource "aws_iam_policy_attachment" "attach_ses_db_lambda_basic_execution_role" {
  name       = "attach_ses_dynomodb_lambda_basic_execution_role"
  roles      = [aws_iam_role.lambda_basic_execution_role.name]
  policy_arn = aws_iam_policy.lambda_policy.arn
}
resource "aws_sns_topic" "sns_topic" {
  name = "topic"
}
resource "aws_dynamodb_table" "table" {
  name           = "dynamodb6225"
  hash_key       = "id"
  read_capacity  = 2
  write_capacity = 2

  attribute {
    name = "id"
    type = "S"
  }
}
resource "aws_lambda_function" "lambda_func" {
  //filename      = "lambda_function_payload.zip"
  function_name = "lambda_func"
  role          = aws_iam_role.lambda_basic_execution_role.arn
  handler       = "index.handler"
  s3_bucket     = "codedeploy.wenhao.min.prod"
  s3_key        = "function.zip"
  //source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs14.x"
}
resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.sns_topic.arn
}
#Create a subscription
resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.sns_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lambda_func.arn
}


# resource "aws_instance" "web" {
#   ami           = data.aws_ami.ubuntu.id
#   instance_type = "t2.micro"
#   tags = {
#     Name = "CodeDeployEC2"
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
#   iam_instance_profile = aws_iam_instance_profile.CodeDeployEC2ServiceRole.name
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
# DB="${aws_db_instance.csye6225.name}"" >> /etc/environment
# EOF
# }


# resource "aws_route53_record" "subdomin-ns" {
#   zone_id = var.profile == "prod" ? "Z0809633154F51HJX4K3" : "Z08074672NPNTYRSOVXG0"
#   name    = var.profile == "prod" ? "prod.wenhaom.me" : "dev.wenhaom.me"
#   type    = "A"
#   ttl     = "60"
#   records = [aws_instance.web.public_ip]
# }


resource "aws_launch_configuration" "asg_launch_config" {
  name                        = "asg_launch_config"
  image_id                    = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  key_name                    = "6225"
  associate_public_ip_address = true
  depends_on                  = [aws_db_instance.csye6225]
  user_data                   = <<EOF
#!/bin/bash
sudo touch .env
sudo echo '#!/bin/bash' > .env
sudo echo "HOST="${aws_db_instance.csye6225.address}."
USERNAME="${aws_db_instance.csye6225.username}"
PASSWORD="${aws_db_instance.csye6225.password}"
Bucket="${aws_s3_bucket.webapp-wenhao-min.id}"
DB="${aws_db_instance.csye6225.name}"" >> /etc/environment
EOF
  iam_instance_profile        = aws_iam_instance_profile.CodeDeployEC2ServiceRole.name

  security_groups = [aws_security_group.application.id]
}

resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  ip_address_type    = "ipv4"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [aws_subnet.subnet1.id, aws_subnet.subnet2.id, aws_subnet.subnet3.id]
}

resource "aws_lb_target_group" "lb_target_group" {
  name                 = "lb-target-group"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = aws_vpc.vpc1234.id
  target_type          = "instance"
  deregistration_delay = 30
  health_check {
    path     = "/mybooks"
    port     = 8080
    interval = 30
  }
}
resource "aws_lb_listener" "app_lb_listener_https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lb_target_group.arn
  }
}


resource "aws_autoscaling_group" "aws_autoscale_gr" {
  name                      = "aws_autoscale_gr"
  default_cooldown          = 60
  launch_configuration      = aws_launch_configuration.asg_launch_config.name
  health_check_grace_period = 300
  health_check_type         = "EC2"
  max_size                  = 5
  min_size                  = 3
  desired_capacity          = 3
  vpc_zone_identifier       = [aws_subnet.subnet1.id, aws_subnet.subnet2.id, aws_subnet.subnet3.id]
  tag {
    key                 = "NAME"
    value               = "autoscaleEC2"
    propagate_at_launch = true
  }
  target_group_arns = [aws_lb_target_group.lb_target_group.arn]
}
resource "aws_autoscaling_policy" "autoscaling_scale_up_policy" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.aws_autoscale_gr.name
}
resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_name         = "CPUAlarmHigh"
  alarm_description  = "Scale-up if CPU > 5% for 60 seconds"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = "60"
  evaluation_periods = "2"
  threshold          = 5
  alarm_actions      = [aws_autoscaling_policy.autoscaling_scale_up_policy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.aws_autoscale_gr.name
  }
  comparison_operator = "GreaterThanThreshold"
}
resource "aws_autoscaling_policy" "autoscaling_scale_down_policy" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.aws_autoscale_gr.name
}
resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name         = "CPUAlarmLow"
  alarm_description  = "Scale-down if CPU < 3% for 60 seconds"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = "60"
  evaluation_periods = "2"
  threshold          = 3
  alarm_actions      = [aws_autoscaling_policy.autoscaling_scale_down_policy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.aws_autoscale_gr.name
  }
  comparison_operator = "LessThanThreshold"
}
resource "aws_codedeploy_app" "example" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}
resource "aws_codedeploy_deployment_group" "example" {
  app_name               = "csye6225-webapp"
  deployment_config_name = "CodeDeployDefault.OneAtATime"
  deployment_group_name  = "csye6225-webapp-deployment"
  service_role_arn       = aws_iam_role.CodeDeployServiceRole.arn
  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.lb_target_group.name
    }
  }
  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  # ec2_tag_set {
  #   ec2_tag_filter {
  #     key   = "NAME"
  #     type  = "KEY_AND_VALUE"
  #     value = "autoscaleEC2"
  #   }
  # }
  autoscaling_groups = [aws_autoscaling_group.aws_autoscale_gr.id]

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

resource "aws_route53_record" "subdomin-ns" {
  zone_id = var.profile == "prod" ? "Z0809633154F51HJX4K3" : "Z08074672NPNTYRSOVXG0"
  name    = var.profile == "prod" ? "prod.wenhaom.me" : "dev.wenhaom.me"
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = false
  }
}




