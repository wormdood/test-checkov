from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck


class AthenaWorkgroupCloudWatch(BaseResourceValueCheck):

    def __init__(self):
        name = "Ensure Athena Workgroup is configured to pubish CloudWatch metrics"
        id = "CKV_AWS_889"
        supported_resources = ['aws_athena_workgroup']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources,
                         missing_block_result=CheckResult.FAILED)

    def get_inspected_key(self):
        return "configuration/[0]/publish_cloudwatch_metrics_enabled"


check = AthenaWorkgroupCloudWatch()
