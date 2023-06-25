terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 4"
      configuration_aliases = [aws, aws.cloudfront]
    }
  }
}

provider "aws" {
  alias  = "acm_provider"
  region = "us-east-1"
}
provider "aws" {
  alias  = "s3_provider"
  region = "ap-south-1"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

# Define the AWS IAM role for the Lambda@Edge function
resource "aws_iam_role" "lambda_edge_role" {
  name = "lambda_edge_role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

data "aws_acm_certificate" "private_website_ssl_certificate" {
  provider    = aws.acm_provider
  domain      = var.domain_name
  //types       = ["AMAZON_ISSUED"]
 // most_recent = true
  //"*.${local.domain_name}"
}
data "aws_iam_policy_document" "read_website_bucket" {
  provider = aws.s3_provider
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.private_website_bucket.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.private_website_bucket.arn]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "read_private_website_bucket_policy" {
  provider = aws.s3_provider
  bucket   = aws_s3_bucket.private_website_bucket.id
  policy   = data.aws_iam_policy_document.read_website_bucket.json
}

resource "aws_s3_bucket_public_access_block" "private_website_bucket" {
  provider                = aws.s3_provider
  bucket                  = aws_s3_bucket.private_website_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_object" "website_files" {
  provider     = aws.s3_provider
  bucket       = aws_s3_bucket.private_website_bucket.id
  key          = "index.html"
  source       = "./index.html"
  content_type = "text/html"
  etag         = filemd5("./index.html")
}
###
#resource "aws_s3_object" "s3_bucket_key_files" {
#  provider     = aws.s3_provider
#  bucket       = aws_s3_bucket.private_website_bucket.id
#  key          = "index.html"
#  source       = "us/index.html"
#  content_type = "text/html"
#  etag         = filemd5("us/index.html")
#}
###
resource "aws_s3_bucket_website_configuration" "website_configuration" {
  provider = aws.s3_provider
  bucket   = aws_s3_bucket.private_website_bucket.bucket
  index_document {
    suffix = "index.html"
  }
}

resource "aws_acm_certificate" "dss_private_website_ssl_certificate" {
  provider          = aws.acm_provider
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "discover-india.info"
}

# Define the AWS CloudFront distribution
resource "aws_cloudfront_distribution" "static_website_distribution" {
  enabled             = true
  origin {
    domain_name = aws_s3_bucket.private_website_bucket.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.private_website_bucket.id 
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }
  price_class = "PriceClass_All"
  logging_config {
    include_cookies = false
    bucket          = "bucket-private-website-log-dss.s3.amazonaws.com"
    prefix          = "private_website/"
  }
  default_root_object = "index.html"
  viewer_certificate {
    acm_certificate_arn = data.aws_acm_certificate.private_website_ssl_certificate.arn //aws_acm_certificate.private_website_ssl_certificate.arn 
    ssl_support_method  = "sni-only"
  }

  # Define the AWS CloudFront behaviors
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["HEAD", "GET"]
    viewer_protocol_policy = "redirect-to-https"
    target_origin_id = aws_s3_bucket.private_website_bucket.id 
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    # Add the Lambda@Edge function as a viewer request function
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.user_details_lambda.qualified_arn
      include_body = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }  
}

# Define the AWS S3 bucket for the static website
resource "aws_s3_bucket" "private_website_bucket" {
  bucket = "my-bucket"
  acl    = "public-read"

  # Define the AWS S3 bucket policy to allow access from the AWS CloudFront origin access identity
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Grant CloudFront Origin Access Identity access to S3 bucket"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn
        }
        Action = "s3:GetObject"
        Resource = "*"
      }
    ]
  })
}

# Define the AWS DynamoDB table for user details
resource "aws_dynamodb_table" "user_details_table" {
  name = "user_details"
  hash_key = "id"
  billing_mode   = "PAY_PER_REQUEST"
  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_policy" "lambda_edge_policy" {
  name = "lambda_edge_policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.user_details_table.arn
      }
    ]
  })
}

# Create a Lambda@Edge function to read user details from DynamoDB
resource "aws_lambda_function" "user_details_lambda" {
  filename      = "user_details_lambda.zip"
  function_name = "user_details_lambda"
  role          = aws_iam_role.lambda_edge_role.arn
  handler       = "user_details_lambda.lambda_handler"
  runtime       = "python3.9"

  # ... other Lambda function configuration ...

  # Define the Lambda function code
#  source_code_hash = filebase64sha256("user_details_lambda.zip")

  # Define the Lambda function environment variables
  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.user_details_table.name
    }
  }
}

resource "aws_iam_role_policy_attachment" "lambda_at_edge_iam_policy_attachment" {
 role = "${aws_iam_role.lambda_edge_role.id}"
 policy_arn = "${aws_iam_policy.lambda_edge_policy.arn}"
}


#data 
data "archive_file" "lambda_file" {
  source_file  = "user_details_lambda.py"
  output_path = "user_details_lambda.zip"
  type        = "zip"
}