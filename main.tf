########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni Search Integration
##  Organization  :   Nasuni - Labss   
#########################################################


data "aws_s3_bucket" "discovery_source_bucket" {
  bucket = local.discovery_source_bucket
}
data "aws_secretsmanager_secret" "user_secrets" {
  name = var.user_secret
}
data "aws_secretsmanager_secret_version" "current_user_secrets" {
  secret_id = data.aws_secretsmanager_secret.user_secrets.id
}

locals {
  discovery_source_bucket = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]
  resource_name_prefix    = "nasuni-labs"
  template_url            = "https://s3.us-east-2.amazonaws.com/unifx-stack/unifx_s3_s3.yml"
  prams = merge(
    var.user_parameters,
    {
      ###################### Read input Parameters from TFVARS file #####################
      SourceBucketAccessKeyID          = var.SourceBucketAccessKeyID != "" ? var.SourceBucketAccessKeyID : data.local_file.accZes.content
      SourceBucketSecretAccessKey      = var.SourceBucketSecretAccessKey != "" ? var.SourceBucketSecretAccessKey : data.local_file.secRet.content
      DestinationBucketAccessKeyID     = var.DestinationBucketAccessKeyID != "" ? var.DestinationBucketAccessKeyID : data.local_file.accZes.content
      DestinationBucketSecretAccessKey = var.DestinationBucketSecretAccessKey != "" ? var.DestinationBucketSecretAccessKey : data.local_file.secRet.content

      ###################### Read input Parameters from Secret Manager #####################
      ProductKey          = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nac_product_key"]
      VolumeKeyParameter  = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["volume_key"]
      VolumeKeyPassphrase = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["volume_key_passphrase"]
      DestinationBucket   = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]

      ###################### Read input Parameters from NMC API #####################
      UniFSTOCHandle = data.local_file.toc.content
      SourceBucket   = data.local_file.bkt.content

      # Read input Parameters from Parameter Store
      /* VolumeKeyPassphrase               = jsondecode(data.aws_ssm_parameter.volume_data.*.value)
      /* VolumeKeyPassphrase               = nonsensitive(jsondecode(jsonencode(data.aws_ssm_parameter.volume_data.value))) */
      ############# Hard coding Parameters ##########################################    
      StartingPoint        = var.StartingPoint
      IncludeFilterPattern = var.IncludeFilterPattern
      IncludeFilterType    = var.IncludeFilterType
      ExcludeFilterPattern = var.ExcludeFilterPattern
      ExcludeFilterType    = var.ExcludeFilterType
      MinFileSizeFilter    = var.MinFileSizeFilter
      MaxFileSizeFilter    = var.MaxFileSizeFilter
      PrevUniFSTOCHandle   = var.PrevUniFSTOCHandle
      DestinationPrefix    = "/nasuni-labs/${var.volume_name}/${data.local_file.toc.content}"
      MaxInvocations       = var.MaxInvocations
    },
  )
}
resource "random_id" "nac_unique_stack_id" {
  byte_length = 6
}
resource "aws_cloudformation_stack" "nac_stack" {
  count = module.this.enabled ? 1 : 0

  name         = "nasuni-labs-AnalyticsConnector-${var.RndIN}"
  tags         = module.this.tags
  template_url = local.template_url
  parameters         = local.prams
  capabilities       = var.capabilities
  on_failure         = var.on_failure
  timeout_in_minutes = var.timeout_in_minutes
  policy_body        = var.policy_body
  depends_on = [data.local_file.accZes,
    data.local_file.secRet,
    aws_secretsmanager_secret_version.internal_secret_u
  ]
}

########################################## Internal Secret  ########################################################

resource "aws_secretsmanager_secret" "internal_secret_u" {
  name        = "nasuni-labs-internal-${var.RndIN}"
  description = "Nasuni Analytics Connector's version specific internal secret. This will be created as well as destroyed along with NAC."
}
resource "aws_secretsmanager_secret_version" "internal_secret_u" {
  secret_id     = aws_secretsmanager_secret.internal_secret_u.id
  secret_string = jsonencode(local.secret_data_to_update)
  depends_on = [
    aws_iam_role.nac_exec_role,aws_secretsmanager_secret.internal_secret_u
  ]
}


locals {
  secret_data_to_update = {
    root_handle                  = data.local_file.toc.content
    discovery_source_bucket      = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]
    nac_stack                    = "nasuni-labs-NasuniAnalyticsConnector-${var.RndIN}"
    aws_region                   = var.region
    user_secret_name             = var.user_secret
    volume_name                  = var.volume_name
    web_access_appliance_address = data.local_file.appliance_address.content
    destination_prefix           = "/nasuni-labs/${var.volume_name}/${data.local_file.toc.content}"
  }
}

############## IAM policy for accessing S3 from a lambda ######################
resource "aws_iam_policy" "s3_GetObject_access" {
  name        = "${local.resource_name_prefix}-ExportOnly_s3_GetObject_access_policy-${var.RndIN}"
  path        = "/"
  description = "IAM policy for accessing S3 from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::*"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-ExportOnly_s3_GetObject_access_policy-${var.RndIN}"
    Application     = "Nasuni Analytics Connector with ExportOnly"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }

}


resource "aws_iam_role" "nac_exec_role" {
  name        = "${local.resource_name_prefix}-nac_exec_role-${var.RndIN}"
  path        = "/"
  description = "Allows NAC to call AWS services on your behalf."

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    Name            = "${local.resource_name_prefix}-nac_exec_role-${var.RndIN}"
    Application     = "Nasuni Analytics Connector with ExportOnly"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

################################### Attaching AWS Managed IAM Policies ##############################################################

data "aws_iam_policy" "CloudWatchFullAccess" {
  arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

data "aws_iam_policy" "AWSCloudFormationFullAccess" {
  arn = "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess"
}

resource "aws_iam_role_policy_attachment" "AWSCloudFormationFullAccess" {
  role       = aws_iam_role.nac_exec_role.name
  policy_arn = data.aws_iam_policy.AWSCloudFormationFullAccess.arn
}

data "aws_iam_policy" "AmazonS3FullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonS3FullAccess" {
  role       = aws_iam_role.nac_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonS3FullAccess.arn
}

data "aws_iam_policy" "AmazonEC2FullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonEC2FullAccess" {
  role       = aws_iam_role.nac_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonEC2FullAccess.arn
}

################################################# END LAMBDA########################################################
# resource "random_id" "r_id" {
#   byte_length = 1
# }RndIN


data "local_file" "secRet" {
  filename   = "${path.cwd}/Zsecret_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}

data "local_file" "accZes" {
  filename   = "${path.cwd}/Zaccess_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}

############################## NMC API CALL ###############################

locals {
  nmc_api_endpoint             = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_endpoint"]
  nmc_api_username             = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_username"]
  nmc_api_password             = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nmc_api_password"]
  web_access_appliance_address = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["web_access_appliance_address"]

}


resource "null_resource" "nmc_api_data" {
 provisioner "local-exec" {
   command = "chmod 755 $(pwd)/*"
  }
   provisioner "local-exec" {
    when    = destroy
    command = "rm -rf *.txt"
  }
}

data "local_file" "toc" {
  filename   = "${path.cwd}/nmc_api_data_root_handle_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "root_handle" {
  value      = data.local_file.toc.content
  depends_on = [data.local_file.toc]
}

data "local_file" "bkt" {
  filename   = "${path.cwd}/nmc_api_data_source_bucket_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}

output "latest_toc_handle_processed" {
  value      = data.local_file.toc.content
  depends_on = [data.local_file.toc]
}


output "source_bucket" {
  value      = data.local_file.bkt.content
  depends_on = [data.local_file.bkt]
}

data "local_file" "v_guid" {
  filename   = "${path.cwd}/nmc_api_data_v_guid_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "volume_guid" {
  value      = data.local_file.v_guid.content
  depends_on = [data.local_file.v_guid]
}


data "local_file" "appliance_address" {
  filename   = "${path.cwd}/nmc_api_data_external_share_url_${var.RndIN}.txt"
  depends_on = [null_resource.nmc_api_data]
}


output "appliance_address" {
  value      = data.local_file.appliance_address.content
  depends_on = [data.local_file.appliance_address]
}

############################################################################
