# OneCloud App update script
# Description: This script takes a file with all VCDs to be updated and updates the ORG url respectively. Output returns success for the apps updated and failure for
#              the apps not found. Please have the clid and clsecret provided for the service client token details
# Author: deekshar@vmware.com and kab@vmware.com
# Version: 1
# Date modified: 20-07-2020

import json
import requests
import base64


# function definitions

def get_encoded(clid, clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    print("Base64encoded string:", baseencoded)
    return baseencoded


def get_access_token(url, header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token


api_urlbase = "https://myvmware.workspaceair.com/SAAS/"

# ENTER CLIENT ID AND SECRET
clid = "gm_cli"
clsecret = "5FwnIOUlTRle0KjwuIizJvqwJPuJHfUP96IbpQWb19w1oW8k"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase + extra, headers)

# Search apps

f = open("/Users/gautamm/Desktop/test.txt", "r")
dec = f.read().splitlines()
searchurl = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/catalogitems/search"
headers2 = {'Content-Type': 'application/vnd.vmware.horizon.manager.catalog.search+json',
            'Accept': 'application/vnd.vmware.horizon.manager.catalog.item.list+json',
            'Authorization': 'Bearer ' + accesstoken}
mainlist = []
for i in dec:
    reqbody = '{ "nameFilter": "' + i + '", "includeTypes":["Saml20"], "categories":["saas"], "includeAttributes":["labels"], "includeIconBytes":"true" }'
    resp = requests.post(searchurl, headers=headers2, data=reqbody)
    jsonresp = json.loads(resp.content)
    tempjsn = jsonresp.get("items")
    sizett = jsonresp.get("totalSize")

    if sizett == 0:
        print("Coudn't find the app :  ", i)
        continue
    dictofids = {}
    dictofids["uuid"] = tempjsn[0].get("uuid")
    dictofids["orgname"] = i
    dictofids["ws1name"] = tempjsn[0].get("name")
    mainlist.append(dictofids)

# print(mainlist)


# Get app information, modify and update app

for nm in mainlist:
    uuid = nm.get("uuid")
    orgname = nm.get("orgname")
    requrl = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/catalogitems/" + uuid
    headers3 = {'Accept': 'application/vnd.vmware.horizon.manager.catalog.saml20+json',
                'Authorization': 'Bearer ' + accesstoken}

    # change the BASE URL name depending on the ORG given by Onecloud team
    baseurl = "https://vcore3-us22.oc.vmware.com/tenant/"

    neworgurl = baseurl + orgname + "/"
    resp1 = requests.get(requrl, headers=headers3)
    json_object = json.loads(resp1.content)
    json_object["authInfo"]["loginRedirectionUrl"] = neworgurl

    # update app
    headers4 = {'Content-Type': 'application/vnd.vmware.horizon.manager.catalog.saml20+json',
                'Accept': 'application/vnd.vmware.horizon.manager.catalog.saml20+json',
                'Authorization': 'Bearer ' + accesstoken}
    updatedbody = json.dumps(json_object)
    newresp = requests.put(requrl, headers=headers4, data=updatedbody)
    print("App update status for: ", nm.get("ws1name"))
    print(newresp)