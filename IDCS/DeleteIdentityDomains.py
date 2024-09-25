import json
import oci

config = oci.config.from_file()


identity_client = oci.identity.IdentityClient(config)

config = json.load(open('config.json'))
domain_id = config["domain_id"]

delete_domain_response = identity_client.delete_domain(
    domain_id)

print(delete_domain_response.headers)
