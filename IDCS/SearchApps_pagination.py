
"""Written for searcing apps in IDCS with pagination"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'


class IAM():

    #import config files
    def __init__(self):
        config = json.load(open('config.json'))
        global idcsURL
        global clientID
        global clientSecret

        idcsURL = config["iamurl"]
        clientID = config["client_id"]
        clientSecret = config["client_secret"]

    #encode client & secret
    def get_encoded(self,clid, clsecret):    #6.
        encoded = clid + ":" + clsecret
        baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
        return baseencoded

    #get access token
    def get_access_token(self,url, header):    #8.
        para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
        response = requests.post(url, headers=header, data=para, verify=False)
        jsonresp = json.loads(response.content)
        access_token = jsonresp.get('access_token')
        return access_token

    #print access token
    def printaccesstoken(self):  #4.
        obj = IAM()
        encodedtoken = obj.get_encoded(clientID, clientSecret)     #5.
        extra = "/oauth2/v1/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                   'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
        accesstoken = obj.get_access_token(idcsURL + extra, headers)     #7.
        return accesstoken


    def searchapps(self):
        obj = IAM()
        accesstoken = obj.printaccesstoken()
        tCount = 500
        startIndex = 0
        count = 50
        loop = int(tCount / count)
        extra = "/admin/v1/Apps"
        headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        for i in range(loop+1):
            param = {'startIndex': startIndex, 'count': count}
            resp = requests.get(idcsURL+extra, headers=headers, verify=False, params=param)
            startIndex += count
            jsonresp1 = json.loads(resp.content)
            tempjsn = jsonresp1.get("Resources")
            for x in tempjsn:
                displayName = x.get("displayName")
                id = x.get("id")
                if displayName == "a1":
                    print(id)
                    break


obj = IAM()   #create an object
obj.searchapps()