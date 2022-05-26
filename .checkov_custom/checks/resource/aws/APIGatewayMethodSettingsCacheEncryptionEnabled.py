from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.enums import CheckCategories


class APIGatewayMethodSettingCacheEncryptionEnabled(BaseResourceValueCheck):

	def __init__(self):
		name = "Ensure API Gateway method setting caching encryption is enabled"
		id = "CKV_AWS_888"
		supported_resources = ['aws_api_gateway_method_settings']
		categories = [CheckCategories.ENCRYPTION]
		super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

	def get_inspected_key(self):
		return "settings/[0]/cache_data_encrypted"


check = APIGatewayMethodSettingCacheEncryptionEnabled()
