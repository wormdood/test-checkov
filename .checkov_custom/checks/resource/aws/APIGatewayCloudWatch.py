from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceCheck


class APIGatewayCloudWatch(BaseResourceCheck):

    def __init__(self):
        self.Passed = False
        name = "Ensure API Gateway is configured to log to CloudWatch (account-level setting).  "
        id = "CKV_AWS_990"
        supported_resources = ['aws_api_gateway_account','aws_api_gateway_rest_api']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    

    def scan_resource_conf(self, conf):
        
        # Check if aws_api_gateway_account resource exists and set self.Passed to True
        if 'cloudwatch_role_arn' in conf:
            self.evaluated_keys = ['cloudwatch_role_arn/[0]']
            self.Passed = True
            return CheckResult.PASSED
        # Check if aws_api_gateway_rest_api resource is being evaluated
        elif 'name' in conf:
            if self.Passed:
                self.evaluated_keys = ['cloudwatch_role_arn/[0]']
                return CheckResult.PASSED
                # Do nothing if we've already found the aws_api_gateway_account resource
                print('already found aws_api_gateway_account resource')
            else:
                # Fail as not aws_api_gateway_account 
                self.evaluated_keys = ['cloudwatch_role_arn/[0]']
                return CheckResult.FAILED
        else:
            # Catch anything weird with a Fail
            self.evaluated_keys = ['cloudwatch_role_arn/[0]']
            return CheckResult.FAILED

check = APIGatewayCloudWatch()

