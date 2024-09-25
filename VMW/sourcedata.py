import json
import requests
import base64
from optparse import OptionParser

def get_encoded(clid, clsecret):
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

def getData():
    api_urlbase = "https://########.########.com/SAAS/"
    clid = "###########"
    clsecret = "#############"
    encodedtoken = get_encoded(clid, clsecret)
    extra = "auth/oauthtoken"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic %s' % encodedtoken}
    accesstoken = get_access_token(api_urlbase + extra, headers)

    key = accesstoken
    print(key)
    header = {}
    header['Authorization'] = "HZN %s" % key
    header['Content-Type'] = "application/vnd.vmware.horizon.manager.catalog.search+json"
    header['Accept'] = "application/vnd.vmware.horizon.manager.catalog.item.list+json"
    data = '{ "nameFilter": "%s", "includeTypes":["Saml11","Saml20","WSFed12","WebAppLink", "AnyApp"], "categories":["saas"], "includeIconBytes":"true" }' % options.search
    u = "%sjersey/manager/api/catalogitems/search?startIndex=0&pageSize=1500" % api_urlbase
    r = requests.request('POST', u, headers=header, data=data, verify=False)
    apps = r.json()

    return apps
    print(apps)

def main(appData):

    usage = "usage: %prog [arg | -f filter] [options]"
    parser = OptionParser(usage)
    parser.add_option("-s", "--search", action="store", type="string", dest="search", default="",
                      help="Search term for application names.")
    # parser.add_option("-t", "--tree", action="store_true", dest="tree", default=False, help="Create Org Tree")

    global options, args
    (options, args) = parser.parse_args()
    print(options.search)

    appData = getData()

    #process = send_data_to_source(appData)
    print(appData)





"""api_urlbase = "https://############.com/SAAS/"
clid = "###########"
clsecret = "###############"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra,headers)

groups=[]
groupsearchurl="https://############.com/SAAS/jersey/manager/api/catalogitems/search?startIndex=0&pageSize=1500&sortBy=displayName
headers2 = {'Content-Type' : 'application/json' , 'Authorization' : 'Bearer ' + accesstoken}
resp = requests.get(groupsearchurl, headers=headers2,verify=False)
print("API call completed")
jsonresp = json.loads(resp.content)
tempjsn = jsonresp.get("Resources")
for group in tempjsn:
    print(group['displayName'])
    tstjson=json.loads(group['urn:scim:schemas:extension:workspace:1.0']['compositionRules'])
    if tstjson['rule'] is None:
        #print(group['displayName']+" has no custom rules ")
        continue
    grouprules = tstjson['rule']['rules']
    for rule in grouprules:
        if rule['type'] == "attribute":
            #print(rule['attribute'])
            if rule['attribute'] == "OrgUnit":
                groups.append(group['displayName'])
print("Below groups are using OrgUnit attribute")
print("-------------")
print(groups)"""
