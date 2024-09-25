"""Written for Source Coveo Platform to extract the Username + groups + emails  in WS1 PROD for all users"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import os
urllib3.disable_warnings()


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

api_urlbase = "https://############.com/SAAS/"
clid = "##########"
clsecret = "############"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Getting Total count of users
searchurl = "https://###########.com/SAAS/jersey/manager/api/scim/Users"
headers2 = {'Authorization': 'Bearer ' + accesstoken}
param = {'attributes': "Username,groups,emails"}
resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
jsonresp = json.loads(resp.content)
totalCount = jsonresp.get("totalResults")
print(totalCount)


#To Get Users
#tcount = 30
startIndex = 1
count = 5000
loop = int(totalCount / count)
mainlist = []
for i in range(loop+1):
    param = {'attributes': "Username,groups,emails", 'startIndex': startIndex, 'count': count}
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    startIndex += count
    jsonresp = json.loads(resp.content)
    tempjsn = jsonresp.get("Resources")
    mainlist.append(tempjsn)
    with open("sample.json", "w") as outfile:
        json.dump(mainlist, outfile)

    print(tempjsn)
with ZipFile('sample.zip', 'w') as zipp:
    zipp.write("sample.json")

