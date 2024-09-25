"""Written for creating users in OCI IAM Identity Domain"""

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

    #create user in bulk from userBulk.json
    def createuser(self):     #2.
        obj = IAM()
        accesstoken = obj.printaccesstoken()   #3.   #9
        extra = "/admin/v1/Bulk"
        headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        users = json.load(open('userBulk.json'))
        print(users)
        payload = json.dumps(users)
        print(type(payload))
        resp = requests.post(idcsURL + extra, headers=headers, verify=False, data=payload)
        print (resp)
        jsonresp = json.loads(resp.content)
        print(jsonresp)


obj = IAM()  # create an object
print(obj.createuser())
