import oci
import json

config = oci.config.from_file()


identity_client = oci.identity.IdentityClient(config)

config = json.load(open('config.json'))
domain_id = config["domain_id"]

deactivate_domain_response = identity_client.deactivate_domain(
    domain_id)


print(deactivate_domain_response.headers)