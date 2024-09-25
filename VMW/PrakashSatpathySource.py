import json
from botocore.vendored import requests
import base64
import logging
from optparse import OptionParser
import requests


import logging

lg = logging.getLogger()
lg.setLevel(logging.INFO)

pSize = 1500

tenant = "w############"
user = "###########"
sharedSecret = "############"
# source_user = "ws1serviceuser"
# source_password = "ws1Service@User!23"

text_str = "%s:%s" % (user, sharedSecret)
byte_str = text_str.encode("utf-8")
secret = base64.b64encode(byte_str)
key = ""

"""text_str_source = "%s:%s" % (source_user, source_password)
byte_str_source = text_str_source.encode("utf-8")
source_secret = base64.b64encode(byte_str_source)
source_secret_str = source_secret.decode("utf-8")

source_user_prod = "ws1serviceuser"
source_password_prod = "ws1Prod@serviceP"
text_str_source_prod = "%s:%s" % (source_user_prod, source_password_prod)
byte_str_source_prod = text_str_source_prod.encode("utf-8")
source_secret_prod = base64.b64encode(byte_str_source_prod)
source_secret_str_prod = source_secret_prod.decode("utf-8")"""

# print(type(text_str))
# print(type(secret))

# print(secret)


"""color = {"True": "\033[32m", "False": "\033[31m", "warn": "\033[0;30;41m", "norm": "\033[0m"}


def send_data_to_source(data):
    header = {}
    header["X-Authorization"] = "Basic ##################"
    header["Content-Type"] = "application/json"
    header["Accept"] = "text/plain"
    API_stg = "https://###########.com/intranet/api/ws1-sourcex"
    #  API_prod = "https://#########com/intranet/api/ws1-sourcex"
    #  r = requests.request('POST', API, headers=header, data=json.dumps(data))
    r_stg = requests.request('POST', API_stg, headers=header, data=json.dumps(data), verify=False)
    API_prod = "https://#############.com/intranet/api/ws1-sourcex"
    r_prod = requests.request('POST', API_prod, headers=header, data=json.dumps(data), verify=False)
    print(r_prod)
    print(r_prod.text)
    print(r_stg)
    print(r_stg.text)"""


def getData():
    global key
    key = getKey()
    header = {}
    header['Authorization'] = "HZN %s" % key
    header['Content-Type'] = "application/vnd.vmware.horizon.manager.catalog.search+json"
    header['Accept'] = "application/vnd.vmware.horizon.manager.catalog.item.list+json"

    data = '{ "nameFilter": "%s", "includeTypes":["Saml11","Saml20","WSFed12","WebAppLink", "AnyApp"], "categories":["saas"], "includeIconBytes":"true" }' % options.search

    u = "https://%s/SAAS/jersey/manager/api/catalogitems/search?startIndex=0&pageSize=1500" % tenant

    r = requests.request('POST', u, headers=header, data=data)
    apps = r.json()

    return apps


def getKey():
    header = {'Content-Type': "application/x-www-form-urlencoded"}
    data = {'grant_type': 'client_credentials'}
    r = requests.post('https://############com/SAAS/auth/oauthtoken', headers=header, params=data,
                      auth=(user, sharedSecret), verify=False)
    token = r.json()['access_token']
    return token


"""def getKey_source():
    header = {}
    header['Authorization'] = "Basic %s" % str(source_secret, 'utf-8')
    header['Content-Type'] = "application/x-www-form-urlencoded"

    data = {'grant_type': 'client_credentials'}

    u = "http://#############.com/intranet/api/auth/oauthtoken"

    r = requests.request('POST', u, headers=header, params=data)
    token_source = r.json()['access_token']

    return token_source"""


def main(appData, process):
    usage = "usage: %prog [arg | -f filter] [options]"
    parser = OptionParser(usage)
    parser.add_option("-s", "--search", action="store", type="string", dest="search", default="",
                      help="Search term for application names.")
    # parser.add_option("-t", "--tree", action="store_true", dest="tree", default=False, help="Create Org Tree")

    global options, args
    (options, args) = parser.parse_args()
    print(options.search)

    appData = getData()
    process = send_data_to_source(appData)


