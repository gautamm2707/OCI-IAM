
"""Written for deleting inactive users from IDCS"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'


def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded
"""parameter = {"grant_type": "client_credentials", "scope":"urn:opc:idm:__myscopes__"}"""
def get_access_token(url,header):

    para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    response = requests.post(url, headers=header,data=para, verify=False)
    print(response.json)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

api_urlbase = "https://idcs-###################.identity.oraclecloud.com"
clid = "################"
clsecret = "####################"
encodedtoken = get_encoded(clid, clsecret)
#print (encodedtoken)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
print (headers)
print (api_urlbase+extra)
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

def del_user(url,header2):

    response = requests.delete(url, headers=header2)
    print(response.json)
    return response

#Getting Total count of users

searchurl = "https://idcs-###################.identity.oraclecloud.com/admin/v1/Users"
headers2 = {'Authorization': 'Bearer ' + accesstoken}
#headers2 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
#param = {'attributes': "Username,groups,emails"}
resp = requests.get(searchurl, headers=headers2, verify=False)
jsonresp = json.loads(resp.content)
totalCount = jsonresp.get("totalResults")
print(totalCount)

#Getting inactive users list

startIndex = 1
count = 50
loop = int(totalCount / count)
f_count = 0
mainlist = []
user_del_url = "https://idcs-#################.identity.oraclecloud.com/admin/v1/Users/"
for i in range(loop+1):
    param = {'attributes': "active,userName,emails", 'startIndex': startIndex, 'count': count}
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    startIndex += count
    jsonresp = json.loads(resp.content)
    tempjsn = jsonresp.get("Resources")
    for x in tempjsn:
        trimjsn = {}
        status = x.get("active")
        print(status)
        if(str(status) == "False"):
            f_count += 1
            user_id = str(x.get("id"))
            del_response = del_user(user_del_url+user_id, headers2)
            print(user_del_url+user_id)
            #resp1 = requests.delete(user_del_url+user_id, headers=headers2)
            #print(resp1)
            #print(resp1.json())
            print(del_response)

print("total inactive users deleted" + str(f_count))
