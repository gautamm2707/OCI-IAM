
"""Written for creating a confidential application for EBS in IDCS"""

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
            param = {'attributes': "id,displayName", 'startIndex': startIndex, 'count': count}
            resp = requests.get(idcsURL + extra, headers=headers, verify=False, params=param)
            startIndex += count
            jsonresp1 = json.loads(resp.content)
            tempjsn = jsonresp1.get("Resources")
            for x in tempjsn:
                displayName = x.get("displayName")
                id = x.get("id")
                if displayName == "EBS Asserter application":
                    obj.deactivateapp(id)
                    obj.deleteapp(id)
                    break

    def deactivateapp(self,id):
        obj = IAM()
        accesstoken = obj.printaccesstoken()
        extra = "/admin/v1/Apps" + "/" + id
        headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        payload = json.dumps({
            "schemas": [
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            ],
            "Operations": [
                {
                    "op": "replace",
                    "path": "active",
                    "value": False
                }
            ]
        })
        response = requests.request("PATCH", idcsURL+extra, headers=headers, data=payload)


    def deleteapp(self,id):
        obj = IAM()
        accesstoken = obj.printaccesstoken()
        extra = "/admin/v1/Apps"+"/"+id
        headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        resp = requests.request("DELETE", idcsURL+extra, headers=headers, verify=False)

    # Create a confidential application
    def createapplication(self):
        obj = IAM()
        obj.searchapps()
        accesstoken = obj.printaccesstoken()
        extra = "/admin/v1/Apps"
        headers = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        para = json.dumps({
            "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
            "basedOnTemplate": {"value": "CustomWebAppTemplateId"},
            "displayName": "EBS Asserter application",
            "description": "Confidential client application for testing purposes",
            "clientType": "confidential",
            "isOAuthClient": True,
            "allowedGrants": ["authorization_code", "client_credentials"],
            "landingPageUrl": "https://ebsasserter.example.com:7004/ebs",
            "active": True,
            "grantedAppRoles": ["Identity Domain Administrator"],
            "redirectUris": ["https://ebsasserter.example.com:7004/ebs/response"],
            "logoutUri": "https://ebsasserter.example.com:7004/ebs/logout",
            "postLogoutRedirectUris": ["https://ebsasserter.example.com:7004/ebs"]

        })
        resp = requests.post(idcsURL+extra, headers=headers, verify=False, data=para)
        jsonresp = json.loads(resp.content)
        clID = jsonresp.get("name")
        clSecret = jsonresp.get("clientSecret")
        appID = jsonresp.get("id")


        extra1 = "/admin/v1/AppRoles"
        headers1 = {'Accept': '*/*', 'Authorization': 'Bearer ' + accesstoken}
        response = requests.request("GET", idcsURL+extra1, headers=headers1)
        jsonresp1 = json.loads(response.content)
        tempjsn = jsonresp1.get("Resources")
        for x in tempjsn:
            displayName = x.get("displayName")
            if displayName == "Authenticator Client":
                approleID1 = x.get("id")
        for x in tempjsn:
            displayName = x.get("displayName")
            if displayName == "Me":
                approleID2 = x.get("id")

        extra2 = "/admin/v1/Grants"
        payload = json.dumps({
            "grantee": {
                "type": "App",
                "value": appID
            },
            "app": {
                "value": "IDCSAppId"
            },
            "entitlement": {
                "attributeName": "appRoles",
                "attributeValue": approleID1
            },
            "grantMechanism": "ADMINISTRATOR_TO_APP",
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
            ]
        })

        payload2 = json.dumps({
            "grantee": {
                "type": "App",
                "value": appID
            },
            "app": {
                "value": "IDCSAppId"
            },
            "entitlement": {
                "attributeName": "appRoles",
                "attributeValue": approleID2
            },
            "grantMechanism": "ADMINISTRATOR_TO_APP",
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
            ]
        })
        headers2 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
        response1 = requests.request("POST", idcsURL+extra2, headers=headers2, data=payload)
        response2 = requests.request("POST", idcsURL + extra2, headers=headers2, data=payload2)
        print(clID)
        #print(clSecret)
        '''with open('clid.txt', 'w') as f:
            f.write(clID)
        with open('secret.txt', 'w') as s:
            s.write(clSecret)
        with open('idcsurl.txt', 'w') as i:
            i.write(idcsURL)'''


obj = IAM()   #create an object
obj.createapplication()


