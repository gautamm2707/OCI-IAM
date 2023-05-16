
"""Written for generating group membership report"""

import json
import requests
import base64
import urllib3
import pandas as pd
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_ = 'ALL:@SECLEVEL=1'

class IAM():

    #import config file
    def __init__(self):
        config = json.load(open('config.json'))
        global idcsURL
        global clientID
        global clientSecret

        idcsURL = config["iamurl"]
        clientID = config["client_id"]
        clientSecret = config["client_secret"]

    #encode client & secret
    def get_encoded(self,clid, clsecret):
        encoded = clid + ":" + clsecret
        baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
        return baseencoded

    #get access token
    def get_access_token(self,url, header):
        para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
        response = requests.post(url, headers=header, data=para, verify=False)
        jsonresp = json.loads(response.content)
        access_token = jsonresp.get('access_token')
        return access_token

    #print access token
    def printaccesstoken(self):
        obj = IAM()
        encodedtoken = obj.get_encoded(clientID, clientSecret)
        extra = "/oauth2/v1/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                   'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
        accesstoken = obj.get_access_token(idcsURL + extra, headers)
        return accesstoken

    #derive total count and then perform json parsing using paging to derive group names for each users.
    def searchusers(self):
        obj = IAM()
        accesstoken = obj.printaccesstoken()
        startIndex = 0
        count = 50
        extra = "/admin/v1/Users"
        headers = {'Accept': '*/*', 'Authorization': 'Bearer ' + accesstoken}
        param = {'attributes': "userName,groups.display", 'startIndex': startIndex, 'count': count}
        resp = requests.get(idcsURL + extra, headers=headers, verify=False, params=param)
        jsonresp = json.loads(resp.content)
        total = jsonresp.get("totalResults")
        print(total)
        tCount = total
        loop = int(tCount / count)
        print(loop)
        mainlist = []
        for i in range(loop + 1):
            param1 = {'attributes': "userName,groups.display", 'startIndex': startIndex, 'count': count}
            resp1 = requests.get(idcsURL + extra, headers=headers, verify=False, params=param1)
            startIndex += count
            jsonresp1 = json.loads(resp1.content)
            tempjsn = jsonresp1.get("Resources")
            for x in tempjsn:
                trimjsn ={}
                user = trimjsn["Username"] = x.get("userName")
                grp = x.get("groups")
                if grp is None:
                    trimjsn["Groups"] = "None"
                    mainlist.append(trimjsn.copy())
                    continue
                for i in grp:
                    grpname = trimjsn["Groups"] = i.get("display")
                    print(trimjsn)
                    mainlist.append(trimjsn.copy())
                print(mainlist)
        return mainlist



obj = IAM()
mainlist = obj.searchusers()

df_mainlist = pd.DataFrame(mainlist)
print(df_mainlist)
df_mainlist.to_csv('mainlist.csv')
