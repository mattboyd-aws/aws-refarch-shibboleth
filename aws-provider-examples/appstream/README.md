# Appstream Setup

- [Appstream Setup](#appstream-setup)
  - [Overview](#overview)
  - [Setup](#setup)
    - [Step 1: Create SP Metadata appstream-metadata.xml](#step-1-create-sp-metadata-appstream-metadataxml)
    - [Step 2: Update metadata-providers.xml](#step-2-update-metadata-providersxml)
    - [Step 3: Update attribute-resolvers.xml](#step-3-update-attribute-resolversxml)
    - [Step 4: Update attribute-filter.xml](#step-4-update-attribute-filterxml)
    - [Step 5: Update saml-nameid.xml](#step-5-update-saml-nameidxml)
    - [Step 6: Update relying-party.xml](#step-6-update-relying-partyxml)
    - [Step 7: Deploy](#step-7-deploy)
    - [Step 8: Test](#step-8-test)
  - [Additional Resources](#additional-resources)

| :information_source: &nbsp;&nbsp; Important| 
|:-|
| If you are using AWS SSO, we suggest using that as an entrypoint for AppStream instead. You can find more details at [this blog post](https://aws.amazon.com/blogs/desktop-and-application-streaming/enable-federation-with-aws-single-sign-on-and-amazon-appstream-2-0/).   | 



## Overview
Appstream uses the same SP metadata as the AWS Console (https://signin.aws.amazon.com/static/saml-metadata.xml). However, to use SAML federation with domain-joined fleets you must pass the domain and username (either `DOMAIN.COM\username` or `username@domain.com`) in the SAML Subject `NameId` of the assertion. Many Shibboleth IdPs are configured to pass a transient (`urn:oasis:names:tc:SAML:2.0:nameid-format:transient` `NameId` by default and will need to be configured to return a different value. Additionally, most customers will want to filter the AWS Roles returned for AppStream, so that users are automatically redirected to their AppStream Fleet and not prompted to select a Role before redirection.

The instructions below will setup the following:

1. A new SP with the EntityId `urn:amazon:appstream`
2. An attribute resolver that returns Roles based on LDAP groups the user belongs to, which begin with `AppStream-[account-id]-[groupname]`. These translated roles are `arn:aws:iam::[account-id]:role/AppStream-[groupname]`. 
3. An attribute filter that releases the appropropriate attributes: `Role`, `RoleSessionName`, and `userPrincipalName` (for `NameID`).
4. An `NameID` and `RelyingParty` configuration that will return the `userPrincipalName` 




## Setup

| :information_source: &nbsp;&nbsp; Important| 
|:-|
| The instructions below are based on a Shibboleth IdP that is using an `AdAuthenticator` and AD-backed LDAP. You may need to specify different attributes in your resolver configuration, depending on your setup. | 


### Step 1: Create SP Metadata appstream-metadata.xml
1. Save the contents of AWS SAML metadata: https://signin.aws.amazon.com/static/saml-metadata.xml as `aws-appstream.xml`, then open it in a text editor. 

2. Replace `entityID="urn:amazon:webservices"` with `entityID="urn:amazon:appstream"` 
3. Remove the `validUntil` element - since we're maintaining a local copy the validity will no longer be updated.
4. Save the file and copy it to the metadata directory on your Shibboleth installation (`/opt/shibboleth-idp/metadata/sp`)

Below is an example of what `aws-appstream.xml` should look like:

```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:amazon:appstream">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDbTCCAlWgAwIBAgIEEvnX2DANBgkqhkiG9w0BAQsFADBnMR8wHQYDVQQDExZ1
cm46YW1hem9uOndlYnNlcnZpY2VzMSIwIAYDVQQKExlBbWF6b24gV2ViIFNlcnZp
Y2VzLCBJbmMuMRMwEQYDVQQIEwpXYXNoaW5ndG9uMQswCQYDVQQGEwJVUzAeFw0y
MDAyMjEwMDAwMDBaFw0yMTAyMjAwMDAwMDBaMGcxHzAdBgNVBAMTFnVybjphbWF6
b246d2Vic2VydmljZXMxIjAgBgNVBAoTGUFtYXpvbiBXZWIgU2VydmljZXMsIElu
Yy4xEzARBgNVBAgTCldhc2hpbmd0b24xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjEjXQm7PrH9OrsayNF8sq5cdYofBC7oloG02
fC+dW8qwtPgg8GETnMEe6HoOjUYaviE5zjYSOGzJBxz6pFK9gxGaMaAP7+VV+H/h
uwn5Vd3DO3nz2TQQ7oQPyp55HutYm8ibyHipEcOiRJzvcCgf7GSZadgfyfK1eC4c
u0s6XRSJpm7rZ5bW0oUh7aXM3Iiv1fP3cm/dYd78nzX8F2tQm4SnEK4/JWqIXO2X
qgCS1KH0Qc378rORnAkB1WwQ3qCyp7aYcRjbpLeijvECDi92lTR/PmpJy9sSDVJt
Aqfgjb1Omphd3+KZ0qgV+kL+xIrnwG6SXgOll27crTJgzso9wQIDAQABoyEwHzAd
BgNVHQ4EFgQUkozq2DgPUAyYvdGakouxXrM3TokwDQYJKoZIhvcNAQELBQADggEB
AAc8z6RMenSuqd+H/+hGDRsdjVWXIoU4I4Ri/vjwZyreAOH5bLuXQq7+oMQWx3fk
iqgQ6qObXywT/aKJwZKVIRlBoBF2n7QoANi4MANLLMrR/WFVDXTX4Lb3f74xGgQF
vywPOff3n83CxQZ9J9H6GDT9cd5s6VDfB1SWvKxOiioqeVkoZYPqHTfWAcA3qgvR
1tpj+ccWTTgP5UH1MSnbibh2f3G/MOaKT/8opZFizXyLS8DKnf8vZ4jU5m6fcsnC
V/CS5Oc9ao+ngMcisM8oEs+tRDDgvvAUBkfsHLY542tkqdcnJDj/dRbNLc7pm/Co
wRuIP2rAXK8JVUhzsC1kzMs=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:entity</NameIDFormat>
    <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://signin.aws.amazon.com/saml"/>
    <AttributeConsumingService index="1">
      <ServiceName xml:lang="en">AWS Management Console Single Sign-On</ServiceName>
      <RequestedAttribute isRequired="true" Name="https://aws.amazon.com/SAML/Attributes/Role" FriendlyName="RoleEntitlement"/>
      <RequestedAttribute isRequired="true" Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName" FriendlyName="RoleSessionName"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" FriendlyName="eduPersonAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2" FriendlyName="eduPersonNickname"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.3" FriendlyName="eduPersonOrgDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.4" FriendlyName="eduPersonOrgUnitDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" FriendlyName="eduPersonPrimaryAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" FriendlyName="eduPersonEntitlement"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.8" FriendlyName="eduPersonPrimaryOrgUnitDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" FriendlyName="eduPersonScopedAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" FriendlyName="eduPersonTargetedID"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" FriendlyName="eduPersonAssurance"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.2" FriendlyName="eduOrgHomePageURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.3" FriendlyName="eduOrgIdentityAuthNPolicyURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.4" FriendlyName="eduOrgLegalName"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.5" FriendlyName="eduOrgSuperiorURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.6" FriendlyName="eduOrgWhitePagesURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:2.5.4.3" FriendlyName="cn"/>
    </AttributeConsumingService>
  </SPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Amazon Web Services, Inc.</OrganizationName>
    <OrganizationDisplayName xml:lang="en">AWS</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://aws.amazon.com</OrganizationURL>
  </Organization>
</EntityDescriptor>

```

### Step 2: Update metadata-providers.xml
1. Open `/opt/shibboleth-idp/conf/metadata-providers.xml`

2. Add a metadata provider element, making sure the `metadataFile` attribute references the path to `aws-appstream.xml` from step 1:

    ```xml
    <MetadataProvider id="AWS-APPSTREAM"  
        xsi:type="FilesystemMetadataProvider" 
        metadataFile="%{idp.home}/metadata/sp/aws-appstream.xml"
        requireValidMetadata="false"
    />    
    ```

### Step 3: Update attribute-resolvers.xml
1. Ensure you've already setup the AWS Attribute resolvers referred to here: [TODO: LINK]. **Do not skip this step.**

2. Open `/opt/shibboleth-idp/conf/attribute-resolvers.xml`. In the `AttributeDefinition`  with `id="idRoles"` add an additional `ValueMap` to map LDAP groups to the AWS roles that will be passed:
    ```xml
    <ValueMap>
        <ReturnValue>arn:aws:iam::$1:role/AppStream-$2,arn:aws:iam::$1:saml-provider/shibboleth</ReturnValue>
    <SourceValue>CN=AppStream-(\d{12})-(\w*),.*</SourceValue>
    </ValueMap>    
    
    ```
    | :information_source: &nbsp;&nbsp; Important| 
    |:-|
    | The value above assumed the SAML Provider in your AWS account is named `arn:aws:iam::[account-id]:saml-provider/shibboleth`. If it's named something else, change it to the correct name, remembering to leave `$1` variable for the account id placeholder| 

    Here is what a complete example might look like, with `ValueMap` elements for both AWS and AppStream:
    ```xml
    <AttributeDefinition id="awsRoles" xsi:type="Mapped">
        <InputDataConnector ref="myLDAP" attributeNames="memberOf"/>
        <AttributeEncoder xsi:type="SAML2String" name="https://aws.amazon.com/SAML/Attributes/Role" friendlyName="Role" />
            <ValueMap>
                <ReturnValue>arn:aws:iam::$1:role/AWS-$2,arn:aws:iam::$1:saml-provider/shibboleth</ReturnValue>
            <SourceValue>CN=AWS-(\d{12})-(\w*),.*</SourceValue>
            </ValueMap>
            <ValueMap>
                <ReturnValue>arn:aws:iam::$1:role/AppStream-$2,arn:aws:iam::$1:saml-provider/shibboleth</ReturnValue>
            <SourceValue>CN=AppStream-(\d{12})-(\w*),.*</SourceValue>
            </ValueMap>     
    </AttributeDefinition>   

3. If not already defined, add an `AttributeDefinition` for `userPrincipalName` to resolve from your LDAP Data Connector (named `myLDAP` in the example below):
    ```xml
    <!-- Resolve userPrincipalName. NOTE: Verify that this  hasn't already been defined elsewhere in attribute-resolver.xml -->   
    <AttributeDefinition xsi:type="Simple" id="userPrincipalName">
        <InputDataConnector ref="myLDAP" attributeNames="userPrincipalName"/>
        <AttributeEncoder xsi:type="SAML2String" name="userPrincipalName" friendlyName="userPrincipalName" encodeType="false" />
    </AttributeDefinition>    
    ```

4. Save `attribute-resolvers.xml`
### Step 4: Update attribute-filter.xml
1. Ensure you've already setup the AWS attribute filters here: [TODO: Likn]. **Do not skip this step.**

2. Open `/opt/shibboleth-idp/conf/attribute-filter.xml`. In the `AttribteFilterPolicy` with id `releaseToAWS` make sure there is a `Rule` entry in `PolicyRequirementRule` for `urn:amazon:appstream`:
    ```xml
        <!-- Custom metadata entity for appstream -->
        <Rule xsi:type="Requester" value="urn:amazon:appstream" />
    ```

3.  Add the following `AttributeFilterPolicy` to release Appstream-specific rules for entity `urn:amazon:appstream`
    ```xml
    <!-- 
        These are the attributes released to AWS for AppStream. This has been separated out so that AppStream users that are
        also assigned to other AWS roles can bypass the role selection screen and go straight to their session. Note: If a user is part of
        multiple "AppStream-" groups, they will still be presented with the role selection screen. Try to assign users to a single group
        and role if possible.
        
        IMPORTANT: Only roles whose names begin with "AppStream-" will be included! This is to filter out roles intended for console use.
        
        IMPORTANT: This filter appies if the requester's EntityId is urn:amazon:appstream. This is a fictitious SP. Create a copy of the 
        aws metadata file, change the EntityId field to urn:amazon:appstream and update metadata-providers.xml to include it. Also be sure
        to include it in relying-party.xml.
        
        https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
        
        https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-assertions
        --> 
        <AttributeFilterPolicy id="releaseAppstreamToAWS">
        <PolicyRequirementRule xsi:type="OR">
            <Rule xsi:type="Requester" value="urn:amazon:appstream" />
        </PolicyRequirementRule>         
            <AttributeRule attributeID="awsRoles">
                <PermitValueRule xsi:type="ValueRegex" regex="arn\:aws\:iam\:\:\d{12}\:role\/AppStream-.*"/>
            </AttributeRule>
        </AttributeFilterPolicy>    
    ```
4. Save `attribute-filters.xml`


### Step 5: Update saml-nameid.xml
1. Ensure you've already setup the SAML NameID policies here: [TODO: Likn]. **Do not skip this step.**

2. Open `/opt/shibboleth-idp/conf/saml-nameid.xml`. There should be a `shibboleth.SAML2AttributeSourcedGenerator` bean with `p:format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" p:attributeSourceIds="#{ {'userPrincipalName'} }"` in it.  Add a `<value>` to `shibboleth.Conditions.RelyingPartyId` for `urn:amazon:appstream`. It should look similar to this:
    ```xml
    <!-- 
    Used for all AWS entities. The AWS Console accepts several NameID formats, including transient but it is recommended to use persistent values.
    
    AppStream2: For Active Directory domain-joined stacks, NameID must be either domain\username (sAMAccountName in Active Directory)
    or username@domain.com (userPrincipalName in ActiveD). 
    
    Best practice for AppStream2 is to set the SAML Subject Type to persistent and put a condition in the AssumeRoleWithSAML clause 
    that verifies sub_type = persistent 
    
    https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-assertions
    
    -->
    <bean parent="shibboleth.SAML2AttributeSourcedGenerator" p:omitQualifiers="true" p:format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" p:attributeSourceIds="#{ {'userPrincipalName'} }">
        <property name="activationCondition">
            <bean parent="shibboleth.Conditions.RelyingPartyId">
                <constructor-arg name="candidates">
                    <list>
                        <value>urn:amazon:webservices</value>
                        <value>urn:amazon:appstream</value>
                    </list>
                </constructor-arg>
            </bean>
        </property>
    </bean>
    ```

3. Save `saml-nameid.xml`

### Step 6: Update relying-party.xml
1. Ensure you've already setup the Relying Party configuration here: [TODO: Likn]. **Do not skip this step.**

2. Locate the `RelyingPartyByName` bean with `p:nameIDFormatPrecedence="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"` that contains the `relyingPartyIds` list value `urn:amazon:webservices`. Add `urn:amazon:appstream` as a list value if it doesn't exist yet. It should look similar to this: 
    ```xml
    <!-- 
    Relying Party Overrides for AWS entities, including custom ones. Though not required by in all cases, NameIDFormatPrecdence is set to persistent as best practice
     -->
    <bean parent="RelyingPartyByName">
        <constructor-arg name="relyingPartyIds">
            <list>
                <value>urn:amazon:webservices</value>
                <value>urn:amazon:appstream</value>
            </list>
        </constructor-arg>               
        <property name="profileConfigurations">
            <list>
                <bean parent="Shibboleth.SSO" />
                <bean parent="SAML2.SSO"
                    p:encryptAssertions="false"
                    p:assertionLifetime="PT5M"
                    p:signResponses="true"
                    p:signAssertions="true"
                    p:includeConditionsNotBefore="true"
                    p:includeAttributeStatement="true"
                    p:nameIDFormatPrecedence="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                    p:additionalAudiencesForAssertion="urn:amazon:webservices"
                    />
                <ref bean="SAML2.ECP" />
                <ref bean="SAML2.Logout" />
                <ref bean="SAML2.AttributeQuery" />
                <ref bean="SAML2.ArtifactResolution" />
            </list>
        </property>
    </bean>     
    ```

3.  Save `relying-party.xml`

### Step 7: Deploy
You can now deploy your updated Shibboleth configuration. If using the refarch, commit and push your changes to the CodeCommit repo to trigger a build.

### Step 8: Test

| :information_source: &nbsp;&nbsp; Important| 
|:-|
| The instructions below are based on an AD-backed Shibboleth IdP. Your details will vary for other backends. The instructions also assume that you have an existing Appstream stack.|

1. Ensure you have already setup Shibboleth as a a [SAML identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml.html) in your AWS accounts and are using the corrent IdP name so that it matches the ARN passed in the SAML assertion.

2. Ensure you have already setup an [IAM role](https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-grantperms) and [policy](https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-embed-inline-policy-for-IAM-role) for Appstream SAML federation. 
    | :information_source: &nbsp;&nbsp; Important| 
    |:-|
    | The IAM role name **MUST** be `Appstream-[group-name]` to match the group name in AD or LDAP.|

3. In Active Directory (or other directory backend), create a Security Group named `Appstream-[account-id]-[group-name]` (i.e. Appstream-123456789012-EngineeringLabs) and assign a test user (i.e. your account) to it. 

4. Create an unsolicited Url that redirects you to your AppStream stack. In the example below, replace the values for `stack` and `accountId`. **Note that `%26` is the ascii code for ampersand (`&`) and should not be removed.**
    ```
    https://shibboleth-host/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:appstream&target=https://appstream2.us-east-1.aws.amazon.com/saml?stack=StackName%26accountId=123456789012
    ```
5. Go to the URL, sign in, and verify that you are successfully redirected to your AppStream stack.

## Additional Resources
- [Appstream 2.0 - Setting up SAML](https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html)
- [Enabling Identity Federation with Shibboleth and Amazon AppStream 2.0](https://aws.amazon.com/blogs/desktop-and-application-streaming/enabling-identity-federation-with-shibboleth-and-amazon-appstream-2-0/)