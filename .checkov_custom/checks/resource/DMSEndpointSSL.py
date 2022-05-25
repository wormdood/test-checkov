from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceCheck


class DMSEndpointSSL(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DMS Endpoint SSL is configured securely.  Endpoint should be secured with a KMS CMK and with the most stringent ssl_mode supported along with a certificate.  See https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL"
        id = "CKV_AWS_259"
        supported_resources = ['aws_dms_endpoint']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        
        kms_key_passed = False
        if 'kms_key_arn' in conf:
            kms_key_passed = True
            self.evaluated_keys = ['kms_key_arn/[0]']
        else:
            kms_key_passed = False
            self.evaluated_keys = ['kms_key_arn/[0]']

        engine = conf['engine_name'][0]        
        
        if engine in ['aurora','mariadb','mysql','sqlserver','postgres','mongodb']:
            ssl_mode_passed = False
            cert_arn_passed = False
            if 'ssl_mode' in conf:
                ssl_mode = conf['ssl_mode'][0]
                if ssl_mode == 'verify-full':
                    ssl_mode_passed = True
                    self.evaluated_keys.append('ssl_mode/[0]')
                else:
                    self.evaluated_keys.append('ssl_mode/[0]')
                    ssl_mode_passed = False
            else: 
                ssl_mode_passed = False
            if 'certificate_arn' in conf:
                cert_arn = conf['certificate_arn'][0]
                cert_arn_passed = True
                self.evaluated_keys.append('certificate_arn/[0]')
            else:
                self.evaluated_keys.append('certificate_arn/[0]')
                cert_arn_passed = False

            if ssl_mode_passed and cert_arn_passed and kms_key_passed:
                return CheckResult.PASSED
            
            return CheckResult.FAILED
        
        elif engine == 'oracle':
            ssl_mode_passed = False
            cert_arn_passed = False

            if 'ssl_mode' in conf:
                ssl_mode = conf['ssl_mode'][0]
                if ssl_mode == 'verify-ca':
                    ssl_mode_passed = True
                    self.evaluated_keys.append('ssl_mode/[0]')
                else:
                    self.evaluated_keys.append('ssl_mode/[0]')
                    ssl_mode_passed = False
            else:
                ssl_mode_passed = False

            if 'certificate_arn' in conf:
                cert_arn = conf['certificate_arn'][0]
                cert_arn_passed = True
                self.evaluated_keys.append('certificate_arn/[0]')
            else:
                self.evaluated_keys.append('certificate_arn/[0]')
                cert_arn_passed = False

            if ssl_mode_passed and cert_arn_passed and kms_key_passed:
                return CheckResult.PASSED
            
            return CheckResult.FAILED

        else:
            if kms_key_passed:
                return CheckResult.PASSED
            return CheckResult.FAILED


check = DMSEndpointSSL()
