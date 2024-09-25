"""Written for Source Coveo Platform to extract the Username + groups + emails  in WS1 PROD for all users"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
import calendar
import time

# Time
ts = calendar.timegm(time.gmtime())
ts = str(ts)

# Source Coveo API details
apiurl = 'https://source-stg.######/intranet/api/ws1-index/?type=user'
username = "#########"
password = "##############"

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

#Getting Total count of users
searchurl = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/scim/Users"
headers2 = {'Authorization': 'Bearer ' + accesstoken}
param = {'attributes': "Username,groups,emails"}
resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
jsonresp = json.loads(resp.content)
totalCount = jsonresp.get("totalResults")
print(totalCount)

#To Get Users
tCount = 5
startIndex = 1
count = 3
loop = int(tCount / count)
mainlist = []
for i in range(loop+1):
    param = {'attributes': "Username,groups,emails", 'startIndex': startIndex, 'count': count}
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    startIndex += count
    jsonresp = json.loads(resp.content)
    tempjsn = jsonresp.get("Resources")
    #mainlist.append(tempjsn)
    #Formatting
    for x in tempjsn:
        trimjsn = {}
        name = trimjsn['userName'] = x.get("userName")
        user_id = x.get("id")
        groups = x.get("groups")
        grp_obj = []
        for g in groups:
            if (g.get("value")):
                grp_obj.append(g.get("value"))
        grp_obj.append(user_id)
        trimjsn["groups"] = grp_obj
        mainlist.append(trimjsn)
        #print(name)
    # END OF THE FORMATTING
    print(mainlist)

# JSON dump
with open("users/users.json", "w") as outfile:
        json.dump(mainlist, outfile)

# Zip using ZipFile library
#with ZipFile('sample.zip', 'w') as zipp:
   # zipp.write("sample.json")

#Zip using make_archive library
path = Path(__file__).parent.absolute()
#create folder e.g. 'userdata' and make siure to write the user json file in that folder
userdata_folder = str(path)+"/users"
shutil.make_archive("users", 'zip', userdata_folder)

#zip file path
user_zip_file = str(path)+"/users.zip"
#print(user_zip_file)

fin = open(user_zip_file, 'rb')
files = {'file': fin}

try:
    r = requests.post(apiurl, files=files, headers=headers3, verify=False)
    print(ts + "   " + r.text)
finally:
    fin.close()
