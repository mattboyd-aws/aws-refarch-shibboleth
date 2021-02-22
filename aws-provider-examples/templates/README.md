# SAML Identity Provider CloudFormation Templates

- [SAML Identity Provider CloudFormation Templates](#saml-identity-provider-cloudformation-templates)
  - [Overview](#overview)
  - [Templates](#templates)
    - [saml-id-cfn.yml](#saml-id-cfnyml)
    - [saml-sample-roles.yml](#saml-sample-rolesyml)
  
## Overview
These CloudFormation templates help setup SAML Identity providers and roles in AWS accounts for SAML Federation into AWS. They can be used as-is or as examples. 

## Templates

### saml-id-cfn.yml

[Template Link](./saml-id-cfn.yml)

This is a Cloudformation Custom Resource Lambda and template that can be used to provision SAML Identity Providers in an AWS Account. The Custom Resource can create an Identity Provider using SAML Metadata provided in a string, via the `Metadata` property, or it can retrieve the Metadata via a Url using the `MetadataUrl` property.

The CloudFormation template [`saml-idp-cfn.yml`](saml-idp-cfn.yml) does the following:
1. Creates a Lambda Execution Role with permission to create, update, and delete SAML Identity Providers and write to CloudWatch Logs
2. Creates a Lambda function that is used by CloudFormation Custom Resource, `Custom::SAMLIdentityProvider`. The source code is in [./src/index.py](src/index.py). 
3. Uses `Custom::SAMLIdentityProvider` to create a SAML Identity Provider in the AWS Account

### saml-sample-roles.yml

[Template Link](./saml-sample-roles.yml)

This template creates several standard roles (and attached policies) in the account:
 - AWS-AccountAdmin (AdministratorAccess)
 - AWS-PowerUser (PowerUserAccess)
 - AWS-NetworkAdmin (NetworkAdministrator)
 - AWS-SysAdmin (SystemAdministrator)
 - AWS-Developer (DataScientist)
 - AWS-ReadOnly (ReadOnlyAccess)
 - AWS-Billing (Billing)
 - AWS-ReadOnlyBilling (ReadOnlyBillingPolicy)

Each of the roles has a trust policy that allows the SAML Identity Provider specified in the `SAMLProviderArn` to federate to.

| :information_source: &nbsp;&nbsp; Important| 
|:-|
| These are sample roles and should be reviewed before deploying!| 
