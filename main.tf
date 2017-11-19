#--------------------------------------------------------------
# terraform config
#--------------------------------------------------------------

terraform {
  required_version = "0.10.8"
}

#--------------------------------------------------------------
# provider
#--------------------------------------------------------------

provider "aws" {
  region = "eu-west-1"
}

#--------------------------------------------------------------
# variables
#--------------------------------------------------------------

variable "logs" {
  description = "CloudWatchLogs Groups and associated Kinesis shard counts"
  type        = "map"

  default = {
    foo = 1
    bar = 2
    baz = 1
  }
}

variable "log_retention" {
  description = "Log retention period in days"
  default     = 365
}

variable "lambda_function_timeout" {
  description = "Number of seconds to pass before timing out Lambda function"
  default     = 15
}

variable "lambda_function_memory_size" {
  description = "Amount of memory in MB the Lambda Function can use at runtime"
  default     = 1024
}

variable "lambda_event_mapping_batch_size" {
  description = "The largest number of records that Lambda will retrieve from your event source (Kinesis) at the time of invocation"
  default     = 100
}

variable "logs_elasticsearch_volume_size" {
  description = "ElasticSearch volume Size"
  default     = 10
}

variable "logs_elasticsearch_instance_type" {
  description = "ElasticSearch instance type"
  default     = "t2.small.elasticsearch"
}

#--------------------------------------------------------------
# input data sources
#--------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_region" "current" {
  current = true
}

data "archive_file" "lambda_logs" {
  type        = "zip"
  source_dir  = "lambda"
  output_path = "logging_pipeline.zip"
}

#--------------------------------------------------------------
# iam
#--------------------------------------------------------------

data "aws_iam_policy_document" "cloudwatchlogs_assume_role" {
  statement {
    sid     = "CloudWatchLogsAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudwatchlogs_assume_role" {
  name               = "cloudwatchlogs_assume_role"
  assume_role_policy = "${data.aws_iam_policy_document.cloudwatchlogs_assume_role.json}"
}

data "aws_iam_policy_document" "cloudwatchlogs_kinesis_policy" {
  statement {
    sid     = "CloudWatchLogsKinesisWrite"
    actions = ["kinesis:PutRecord"]
    effect  = "Allow"

    resources = [
      "${formatlist("%s", aws_kinesis_stream.logs.*.arn)}",
    ]
  }

  statement {
    sid     = "CloudWatchLogsPassRole"
    actions = ["iam:PassRole"]
    effect  = "Allow"

    resources = [
      "${aws_iam_role.cloudwatchlogs_assume_role.arn}",
    ]
  }
}

resource "aws_iam_role_policy" "cloudwatchlogs_kinesis_policy" {
  name   = "cloudwatchlogs_kinesis_policy"
  role   = "${aws_iam_role.cloudwatchlogs_assume_role.name}"
  policy = "${data.aws_iam_policy_document.cloudwatchlogs_kinesis_policy.json}"
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "LambdaAssumeRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_assume_role" {
  name               = "lambda_assume_role"
  assume_role_policy = "${data.aws_iam_policy_document.lambda_assume_role.json}"
}

data "aws_iam_policy_document" "lambda_logs_policy" {
  statement {
    sid = "LambdaLogsInvokeFunction"

    actions = [
      "lambda:InvokeFunction",
    ]

    effect = "Allow"

    resources = [
      "${formatlist("%s", aws_lambda_function.logs.*.arn)}",
    ]
  }

  statement {
    sid = "LambdaLogsKinesisRead"

    actions = [
      "kinesis:GetRecords",
      "kinesis:GetShardIterator",
      "kinesis:DescribeStream",
      "kinesis:ListStreams",
    ]

    effect = "Allow"

    resources = [
      "${formatlist("%s", aws_kinesis_stream.logs.*.arn)}",
    ]
  }

  statement {
    sid = "LambdaLogsCloudWatchLogs"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    effect = "Allow"

    resources = [
      "${formatlist("%s", aws_cloudwatch_log_group.lambda_logs.*.arn)}",
    ]
  }

  statement {
    sid = "LambdaLogsKMSDecrypt"

    actions = [
      "kms:Decrypt*",
      "kms:Describe*",
    ]

    effect = "Allow"

    resources = [
      "${aws_kms_key.logs.arn}",
    ]
  }

  statement {
    sid = "LambdaLogsElasticSearch"

    actions = [
      "es:ESHttpPost",
    ]

    effect = "Allow"

    resources = [
      "${aws_elasticsearch_domain.logs.arn}",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_logs_policy" {
  name   = "lambda_logs_policy"
  role   = "${aws_iam_role.lambda_assume_role.name}"
  policy = "${data.aws_iam_policy_document.lambda_logs_policy.json}"
}

data "aws_iam_policy_document" "logs_kms_key_policy" {
  statement {
    sid     = "KMSAccount"
    actions = ["kms:*"]
    effect  = "Allow"

    resources = [
      "*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid = "KMSCloudWatchLogs"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    effect = "Allow"

    resources = [
      "*",
    ]

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    principals {
      type        = "AWS"
      identifiers = ["${aws_iam_role.cloudwatchlogs_assume_role.arn}"]
    }
  }
}

#--------------------------------------------------------------
# resources
#--------------------------------------------------------------

resource "aws_kms_key" "logs" {
  description             = "KMS key for logs"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = "${data.aws_iam_policy_document.logs_kms_key_policy.json}"
}

resource "aws_kms_alias" "logs" {
  name          = "alias/logging_pipeline"
  target_key_id = "${aws_kms_key.logs.key_id}"
}

resource "aws_cloudwatch_log_group" "logs" {
  count             = "${length(keys(var.logs))}"
  name              = "${element(keys(var.logs), count.index)}"
  kms_key_id        = "${aws_kms_key.logs.arn}"
  retention_in_days = "${var.log_retention}"
}

resource "aws_kinesis_stream" "logs" {
  count           = "${length(keys(var.logs))}"
  name            = "${element(keys(var.logs), count.index)}"
  encryption_type = "KMS"
  kms_key_id      = "${aws_kms_key.logs.key_id}"
  shard_count     = "${lookup(var.logs, element(keys(var.logs), count.index))}"
}

resource "aws_cloudwatch_log_subscription_filter" "logs" {
  count           = "${length(keys(var.logs))}"
  destination_arn = "${element(aws_kinesis_stream.logs.*.arn, count.index)}"
  filter_pattern  = "[]"
  log_group_name  = "${element(aws_cloudwatch_log_group.logs.*.name, count.index)}"
  name            = "${element(keys(var.logs), count.index)}"
  role_arn        = "${aws_iam_role.cloudwatchlogs_assume_role.arn}"
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  count             = "${length(keys(var.logs))}"
  name              = "/aws/lambda/${element(keys(var.logs), count.index)}"
  kms_key_id        = "${aws_kms_key.logs.arn}"
  retention_in_days = "${var.log_retention}"
}

resource "aws_lambda_function" "logs" {
  count            = "${length(keys(var.logs))}"
  filename         = "${data.archive_file.lambda_logs.output_path}"
  function_name    = "${element(keys(var.logs), count.index)}"
  handler          = "exports.handler"
  kms_key_arn      = "${aws_kms_key.logs.arn}"
  memory_size      = "${var.lambda_function_memory_size}"
  role             = "${aws_iam_role.lambda_assume_role.arn}"
  runtime          = "nodejs6.10"
  source_code_hash = "${base64sha256(file("${data.archive_file.lambda_logs.output_path}"))}"
  timeout          = "${var.lambda_function_timeout}"

  environment {
    variables = {
      ES_ENDPOINT = "${aws_elasticsearch_domain.logs.endpoint}"
    }
  }
}

resource "aws_lambda_event_source_mapping" "logs" {
  count             = "${length(keys(var.logs))}"
  batch_size        = "${var.lambda_event_mapping_batch_size}"
  event_source_arn  = "${element(aws_kinesis_stream.logs.*.arn, count.index)}"
  enabled           = true
  function_name     = "${element(aws_lambda_function.logs.*.arn, count.index)}"
  starting_position = "TRIM_HORIZON"
}

resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "logs"
  elasticsearch_version = "5.5"

  ebs_options = {
    ebs_enabled = true
    volume_type = "gp2"
    volume_size = "${var.logs_elasticsearch_volume_size}"
  }

  cluster_config = {
    instance_type = "${var.logs_elasticsearch_instance_type}"
  }

  access_policies = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
              "es:ESHttpGet",
              "es:ESHttpPut",
              "es:ESHttpPost",
              "es:ESHttpHead",
              "es:ESHttpDelete",
              "es:Describe*",
              "es:List*"
            ],
            "Principal": "*",
            "Effect": "Allow",
            "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/logs/*"
        }
    ]
}
EOF
}
