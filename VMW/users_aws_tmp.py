import json
import base64
# from botocore.vendored import requests
import logging
import shutil
import urllib3
from pathlib import Path
import requests

from shutil import copyfile
from os import chdir, environ as env, makedirs
import os.path as path
import subprocess

urllib3.disable_warnings()

# Source Coveo API details
apiurl = 'https://sourcex-dev.vmware.com/intranet/api/ws1-index/?type=user'
username = "ws1serviceuser"
password = "ws1@serviceP"

basicAuth = username + ":" + password
basicAuth = basicAuth.encode('ascii')
basicAuth = base64.b64encode(basicAuth)
basicAuth = basicAuth.decode('ascii')
headers3 = {'X-Authorization': 'Basic ' + basicAuth}


def get_encoded(clid, clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    # print("Base64encoded string:", baseencoded)
    return baseencoded


def get_access_token(url, header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter, verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token


def print_access_token(clid, clsecret):
    api_urlbase = "https://myvmware.workspaceair.com/SAAS/"
    encodedtoken = get_encoded(clid, clsecret)
    extra = "auth/oauthtoken"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic %s' % encodedtoken}
    accesstoken = get_access_token(api_urlbase + extra, headers)
    return accesstoken


# Getting Total count of users
def get_totalCount(accesstoken, searchurl, headers2, param):
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    jsonresp = json.loads(resp.content)
    totalCount = jsonresp.get("totalResults")
    return totalCount


# To Get Users
def get_users(searchurl, headers2):
    tCount = 11
    startIndex = 1
    count = 3
    loop = int(tCount / count)
    mainlist = []
    for i in range(loop + 1):
        param = {'attributes': "Username,groups,emails", 'startIndex': startIndex, 'count': count}
        resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
        startIndex += count
        jsonresp = json.loads(resp.content)
        tempjsn = jsonresp.get("Resources")
        # mainlist.append(tempjsn)
        # Formatting
        for x in tempjsn:
            trimjsn = {}
            name = trimjsn['userName'] = x.get("userName")
            user_id = trimjsn['id'] = x.get("id")
            groups = x.get("groups")
            mainlist.append(trimjsn)
            grp_obj = []
            for g in groups:
                if (g.get("value")):
                    grp_obj.append(g.get("value"))
            mainlist.append(grp_obj)

            # print(name)
        # END OF THE FORMATTING
    return mainlist


"""
# JSON dump
with open("users/users.json", "w") as outfile:
        json.dump(mainlist, outfile)
# Zip
#with ZipFile('sample.zip', 'w') as zipp:
   # zipp.write("sample.json")


path = Path(__file__).parent.absolute()
#create folder e.g. 'userdata' and make siure to write the user json file in that folder
userdata_folder = str(path)+"/users"
shutil.make_archive("users", 'zip', userdata_folder)

#zip file path
user_zip_file = str(path)+"/users.zip"
print(user_zip_file)
"""


def main(event, lambda_context):
    clid = "gm_cli"
    clsecret = "5FwnIOUlTRle0KjwuIizJvqwJPuJHfUP96IbpQWb19w1oW8k"
    searchurl = "https://myvmware.workspaceair.com/SAAS/jersey/manager/api/scim/Users"

    param = {'attributes': "Username,groups,emails"}
    access_token = print_access_token(clid, clsecret)
    headers2 = {'Authorization': 'Bearer ' + access_token}
    count1 = get_totalCount(access_token, searchurl, headers2, param)
    users_mainlist = get_users(searchurl, headers2)

    # Set working dir to /tmp as lambda only has access to that
    tmp_dir = "/tmp/users"
    token_path = path.join(tmp_dir, 'users.json')
    print(token_path)
    try:
        makedirs(tmp_dir)
        print("1")
        subprocess.run(["chmod", "775", str(tmp_dir)])
        print("2")
        with open("/tmp/users/users.json", "w") as outfile:
            json.dump(users_mainlist, outfile)
        print("3")
        """copyfile('/tmp/users/users.json', token_path)
        print("4")
        print("Created directory / copied file")
        print("5")"""
    except:
        pass
    print("Entered Except")
    chdir(tmp_dir)
    path1 = Path(__file__).parent.absolute()
    userdata_folder = str(path1) + tmp_dir
    shutil.make_archive("users", 'zip', userdata_folder)


"""
    # zip file path
    user_zip_file = str(path) + "/users.zip"
    print(user_zip_file)

    fin = open(user_zip_file, 'rb')
    files = {'file': fin}

    try:
        r = requests.post(apiurl, files=files, headers=headers3, verify=False)
        print(r.text)
    finally:
        fin.close()

    print(access_token)
    print(count1)
    print(users_mainlist)
"""
if __name__ == "__main__":
    main()