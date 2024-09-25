

"""Written for Source Coveo Platform to extract the Subject IDs for each applications in WS1 PROD, and then trim the JSON and Zip it.
  TRIMMED JSON + APPID + SUBJECTID RESPONSE"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'

apiurl = 'https://source-stg.vmware.com/intranet/api/ws1-index/?type=user'
username = "ws1serviceuser"
password = "ws1Service@User!23"

basicAuth = username+":"+password
basicAuth = basicAuth.encode('ascii')
basicAuth = base64.b64encode(basicAuth)
basicAuth = basicAuth.decode('ascii')
headers3 = {'X-Authorization': 'Basic '+basicAuth}

def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded

def get_access_token(url,header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter, verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

api_urlbase = "https://myvmware.workspaceair.com/SAAS/"
clid = "gm_cli"
clsecret = "5FwnIOUlTRle0KjwuIizJvqwJPuJHfUP96IbpQWb19w1oW8k"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Getting Apps ID
searchurl = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/catalogitems/search?startIndex=0&pageSize=2000"
headers2 = {'Authorization': 'Bearer ' + accesstoken, 'Accept': 'application/vnd.vmware.horizon.manager.catalog.item.list+json' , 'Content-Type': 'application/vnd.vmware.horizon.manager.catalog.search+json'}
data = '{"includeTypes":["Saml11","Saml20","WSFed12","WebAppLink", "AnyApp"], "categories":[], "rootResource":"false" }'
resp = requests.post(searchurl, headers=headers2, verify=False, data=data)

jsonresp = json.loads(resp.content)
tempjsn = jsonresp.get("items")
size = jsonresp.get("totalSize")
#print(tempjsn)
#print(size)
mainapplist = []
mainsubjectidlist =[]
c = 0
for i in range(2):
    appId = tempjsn[i].get("uuid")
    c += 1
#trimthejson
    if (tempjsn[i].get("visible") == True):

        trimjson = {}
        trimjson["uuid"] = tempjsn[i].get("uuid")
        name = trimjson["name"] = tempjsn[i].get("name")
        trimjson["description"] = tempjsn[i].get("description")
        trimjson["catalogItemType"] = tempjsn[i].get("catalogItemType")
        trimjson["labels"] = tempjsn[i].get("labels")
        trimjson["visible"] = tempjsn[i].get("visible")
        trimjson["internal"] = tempjsn[i].get("internal")
        trimjson["_links"] = tempjsn[i].get("_links")
        #trimjson["items"] = tempjsn[i].get("items")
        #print(name)
        #print(c)
    #toextractsubjectids
        u = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/entitlements/definitions/catalogitems/"+appId
        headers4 = {'Authorization': 'Bearer ' + accesstoken,
                    'Accept': 'application/vnd.vmware.horizon.manager.entitlements.v2.definition.list+json',
                    'Content-Type': 'application/vnd.vmware.horizon.manager.entitlements.v2.definition.list+json'}
        resp1 = requests.get(u, headers=headers4, verify=False)
        jsonresp1 = json.loads(resp1.content)
        trimjson["items"] = jsonresp1['items']
        mainapplist.append(trimjson)
        #mainapplist.append(appId)
        #mainapplist.append(jsonresp1)

print(mainapplist)

"""
with open("app.json", "w") as outfile:
    json.dump(mainapplist, outfile)
with ZipFile('app.zip', 'w') as zipp:
    zipp.write("app.json")
print(mainapplist)
"""
# JSON dump
with open("apps/apps.json", "w") as outfile:
    json.dump(mainapplist, outfile)

# Zip using ZipFile library
#with ZipFile('sample.zip', 'w') as zipp:
   # zipp.write("sample.json")

#Zip using make_archive library
path = Path(__file__).parent.absolute()
#create folder e.g. 'userdata' and make siure to write the user json file in that folder
userdata_folder = str(path)+"/apps"
shutil.make_archive("apps", 'zip', userdata_folder)

#zip file path
user_zip_file = str(path)+"/apps.zip"
#print(user_zip_file)

fin = open(user_zip_file, 'rb')
files = {'file': fin}
"""
try:
    r = requests.post(apiurl, files=files, headers=headers3, verify=False)
    print(r.text)
finally:
    fin.close()
"""