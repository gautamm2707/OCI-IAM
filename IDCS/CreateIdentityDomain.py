import oci

# Create a default config using DEFAULT profile in default location
# Refer to
# https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File
# for more info
config = oci.config.from_file()


# Initialize service client with default config file
identity_client = oci.identity.IdentityClient(config)


# Send the request to service, some parameters are not required, see API
# doc for more info
create_domain_response = identity_client.create_domain(
    create_domain_details=oci.identity.models.CreateDomainDetails(
        compartment_id="ocid1.compartment.oc1..#############",
        display_name="#########",
        description="############",
        home_region="us-ashburn-1",
        license_type="Free",
        is_hidden_on_login=False,
        admin_first_name="#######",
        admin_last_name="Soni",
        admin_user_name="##########",
        admin_email="###########",
        is_notification_bypassed=False,
        is_primary_email_required=True))


# Get the data from response
print(create_domain_response.headers)

'''freeform_tags={
            'EXAMPLE_KEY_8k0We': 'EXAMPLE_VALUE_5EJC6zQURC0zwSgrobUw'},
        defined_tags={
            'EXAMPLE_KEY_jpwex': {
                'EXAMPLE_KEY_8sEcO': 'EXAMPLE--Value'}}),
    opc_retry_token="EXAMPLE-opcRetryToken-Value",
    opc_request_id="BQLWUFZ2JGSROJJL3MTZ<unique_ID>")'''