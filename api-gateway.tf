resource "aws_api_gateway_account" "demo" {
  cloudwatch_role_arn = aws_iam_role.cloudwatch.arn
}

resource "aws_iam_role" "cloudwatch" {
  name = "api_gateway_cloudwatch_global"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudwatch" {
  name = "default"
  role = aws_iam_role.cloudwatch.id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:FilterLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_api_gateway_rest_api" "ok_example" {
  name = "ok_example"

  body = jsonencode({
    openapi = "3.0.1"
    info = {
      title   = "ok_example"
      version = "1.0"
    }
    paths = {
      "/path1" = {
        get = {
          x-amazon-apigateway-integration = {
            httpMethod           = "GET"
            payloadFormatVersion = "1.0"
            type                 = "HTTP_PROXY"
            uri                  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
          }
        }
      }
    }
  })

}

resource "aws_api_gateway_deployment" "ok_example" {
  rest_api_id = aws_api_gateway_rest_api.ok_example.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.ok_example.body))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "ok_example" {
  deployment_id = aws_api_gateway_deployment.ok_example.id
  rest_api_id   = aws_api_gateway_rest_api.ok_example.id
  stage_name    = "ok_example"
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.ok_example.id
  stage_name  = aws_api_gateway_stage.ok_example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "ERROR"
  }
}

resource "aws_api_gateway_method_settings" "path_specific" {
  rest_api_id = aws_api_gateway_rest_api.ok_example.id
  stage_name  = aws_api_gateway_stage.ok_example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = true
    cache_data_encrypted = true
  }
}

# Bad Example 1 - Not connected or connected with wrong logs errors


resource "aws_api_gateway_deployment" "not_connected" {
  rest_api_id = aws_api_gateway_rest_api.not_connected.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.not_connected.body))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "not_connected" {
  deployment_id = aws_api_gateway_deployment.not_connected.id
  rest_api_id   = aws_api_gateway_rest_api.not_connected.id
  stage_name    = "not_connected"
}


resource "aws_apigatewayv2_api" "example" {
  name          = "example-http-api"
  protocol_type = "HTTP"
}
