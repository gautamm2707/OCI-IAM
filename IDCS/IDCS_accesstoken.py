
"""Written for obtaining access token from IDCS"""

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
    return baseencoded

def get_access_token(url,header):

    para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    response = requests.post(url, headers=header,data=para, verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

api_urlbase = "https://idcs-################.identity.oraclecloud.com"
clid = "############"
clsecret = "#################"
encodedtoken = get_encoded(clid, clsecret)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)
