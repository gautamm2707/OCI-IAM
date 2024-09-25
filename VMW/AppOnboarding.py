import json
import requests
import base64
import urllib3
urllib3.disable_warnings()

#Base64encoding
def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded

#GeneratingAccessToken
def get_access_token(url,header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter, verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

#main
api_urlbase = "https://ws-cet-vidm1.#######/SAAS/"
clid = "##############"
clsecret = "##############"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra, headers)
#print(accesstoken)

#Taking Inputs for the Application
name = input("Application Name : ")
name.strip()
description = input("Description : ")
description.strip()
icon = input("Icon URL : ")
icon.strip()
groups = input("Group Name : ")
groups.strip()
m = input("Metadata URL : ")
metadataUrl = m.rstrip()
orgUrl = input("Org Url : ")
orgUrl.strip()


#InsertApp
url = "https://ws-cet-vidm1.vmware.com/SAAS/jersey/manager/api/catalogitems"
headers2 = {'Content-Type' : 'application/vnd.vmware.horizon.manager.catalog.saml20+json' , 'Accept' : 'application/vnd.vmware.horizon.manager.catalog.saml20+json', 'Authorization' : 'Bearer ' + accesstoken}
#payload = "{   \n   \"catalogItemType\":\"Saml20\",\n   \"uuid\":\"59b0e922-fde4-468e-9c63-40a152c465a9\",\n   \"packageVersion\":\"1.0\",\n   \"name\":\"Onecloud Test App\",\n   \"productVersion\":null,\n   \"description\":\"Onecloud Test App\",\n   \"provisioningAdapter\":null,\n   \"resourceConfiguration\":null,\n   \"cdnIconUrl\": \"https://us01-0-umbrella1.oc.vmware.com/v1/util/ams2-vcd01/emea-sddc-lt-labs/app_icon\",\n   \"iconBytes\":null,\n   \"accessPolicySetUuid\":null,\n   \"labels\": [\n                {\n                    \"id\": \"64184\",\n                    \"name\": \"TestAPI\",\n                    \"_links\": {}\n                }\n            ],\n   \"uiCapabilities\":{   \n      \"catalogItemEntitlement\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemDetails\":[   \n         \"READ\",\n         \"EXPORT\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemAccessPolicy\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemProvisioning\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemLicense\":[   \n         \"READ\",\n         \"UPDATE\"\n      ]\n   },\n   \"authInfo\":{   \n      \"type\":\"Saml20\",\n      \"validityTimeSeconds\":200,\n      \"parameters\":null,\n      \"attributes\": [\n        {\n            \"name\": \"EmailAddress\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.email}\"\n        },\n        {\n            \"name\": \"Username\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.userName}\"\n        },\n        {\n            \"name\": \"FullName\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.firstName} ${user.lastName}\"\n        },\n        {\n            \"name\": \"Groups\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"c_us05-1-onecloudcso-t-admins\"\n        }\n    ],\n      \"configureAs\":\"url\",\n      \"metadata\":\"\",\n      \"metadataUrl\":\"https://ams2-vcd01.oc.vmware.com/cloud/org/ams2-vcd01-emea-sddc-lt-labs-t/saml/metadata/alias/vcd\",\n      \"includeDestination\":true,\n      \"signAssertion\":true,\n      \"signResponse\":true,\n      \"includeSigningCert\":false,\n      \"loginRedirectionUrl\":\"https://vcore1-us05.oc.vmware.com/cloud/org/us05-1-onecloudcso-t/\",\n      \"relayState\":\"\",\n      \"encryptionCerts\":null,\n      \"allowApiAccess\":false,\n      \"credentialCheckType\":null,\n      \"proxyCount\":null\n   }\n}\n"
payload = "{   \n   \"catalogItemType\":\"Saml20\",\n   \"uuid\":\"59b0e922-fde4-468e-9c63-40a152c465a9\",\n   \"packageVersion\":\"1.0\",\n   \"name\": \"%s\" ,\n   \"productVersion\":null,\n   \"description\":\"%s\",\n   \"provisioningAdapter\":null,\n   \"resourceConfiguration\":null,\n   \"cdnIconUrl\": \"%s\",\n   \"iconBytes\":null,\n   \"accessPolicySetUuid\":null,\n   \"labels\": [\n                {\n                    \"id\": \"64184\",\n                    \"name\": \"TestAPI\",\n                    \"_links\": {}\n                }\n            ],\n   \"uiCapabilities\":{   \n      \"catalogItemEntitlement\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemDetails\":[   \n         \"READ\",\n         \"EXPORT\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemAccessPolicy\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemProvisioning\":[   \n         \"READ\",\n         \"DELETE\",\n         \"CREATE\",\n         \"UPDATE\"\n      ],\n      \"catalogItemLicense\":[   \n         \"READ\",\n         \"UPDATE\"\n      ]\n   },\n   \"authInfo\":{   \n      \"type\":\"Saml20\",\n      \"validityTimeSeconds\":200,\n      \"parameters\":null,\n      \"attributes\": [\n        {\n            \"name\": \"EmailAddress\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.email}\"\n        },\n        {\n            \"name\": \"Username\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.userName}\"\n        },\n        {\n            \"name\": \"FullName\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"${user.firstName} ${user.lastName}\"\n        },\n        {\n            \"name\": \"Groups\",\n            \"nameFormat\": \"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\",\n            \"nameSpace\": \"\",\n            \"value\": \"%s\"\n        }\n    ],\n      \"configureAs\":\"url\",\n      \"metadata\":\"\",\n      \"metadataUrl\":\"%s\",\n      \"includeDestination\":true,\n      \"signAssertion\":true,\n      \"signResponse\":true,\n      \"includeSigningCert\":false,\n      \"loginRedirectionUrl\":\"%s\",\n      \"relayState\":\"\",\n      \"encryptionCerts\":null,\n      \"allowApiAccess\":false,\n      \"credentialCheckType\":null,\n      \"proxyCount\":null\n   }\n}\n" % (name,description,icon, groups, metadataUrl, orgUrl)
response = requests.request("POST", url, headers=headers2, data=payload, verify=False)
print(response.text.encode('utf8'))


#LabelAssignment
url2 = "https://ws-cet-vidm1.vmware.com/SAAS/jersey/manager/api/labeler"
payload1 = "{\n    \"catalogItems\":[\n        \"/SAAS/jersey/manager/api/catalogitems/59b0e922-fde4-468e-9c63-40a152c465a9\"\n        ],\n    \"labelsToAdd\":[\n        \"/SAAS/jersey/manager/api/labels/54\"\n        ],\n    \"labelsToRemove\" : []\n}"
headers3 = {'Accept': 'application/vnd.vmware.horizon.manager.labelerreq+json','Content-Type': 'application/vnd.vmware.horizon.manager.labelerreq+json','Authorization': 'Bearer ' + accesstoken}
response = requests.request("PUT", url2, headers=headers3, data=payload1, verify=False)
print(response.text.encode('utf8'))
