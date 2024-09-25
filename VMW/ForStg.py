"""Written for Source Coveo Platform to extract the Subject IDs for each applications in WS1 PROD, and then trim the JSON and Zip it.
  TRIMMED JSON + APPID + SUBJECTID RESPONSE"""
import gzip
import json
import requests
import base64
import urllib3

urllib3.disable_warnings()


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

api_urlbase = "https://#####.#########/SAAS/"
clid = "g######"
clsecret = "##################"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Getting Apps ID
searchurl = "https://myvmware-stg.############.#####/SAAS/jersey/manager/api/catalogitems/search?startIndex=0&pageSize=1500"
headers2 = {'Authorization': 'Bearer ' + accesstoken, 'Accept': 'application/vnd.vmware.horizon.manager.catalog.item.list+json' , 'Content-Type': 'application/vnd.vmware.horizon.manager.catalog.search+json'}
data = '{"includeTypes":["Saml11","Saml20"], "categories":[], "rootResource":"false" }'
resp = requests.post(searchurl, headers=headers2, verify=False, data=data)
jsonresp = json.loads(resp.content)
tempjsn = jsonresp.get("items")
size = jsonresp.get("totalSize")

#print(tempjsn)
print(size)
mainapplist = []
mainsubjectidlist =[]
c = 0
for i in tempjsn:
    appId = i.get("uuid")
    c += 1
#trimthejson
    trimjson = {}
    trimjson["uuid"] = i.get("uuid")
    name = trimjson["name"] = i.get("name")
    trimjson["description"] = i.get("description")
    trimjson["catalogItemType"] = i.get("catalogItemType")
    trimjson["labels"] = i.get("labels")
    trimjson["visible"] = i.get("visible")
    trimjson["internal"] = i.get("internal")
    trimjson["_links"] = i.get("_links")
    trimjson["items"] = i.get("items")
    print(name)
    print(c)
#toextractsubjectids
    u = "https://######.########.########/SAAS/jersey/manager/api/entitlements/definitions/catalogitems/"+appId
    headers3 = {'Authorization': 'Bearer ' + accesstoken,
                'Accept': 'application/vnd.vmware.horizon.manager.entitlements.v2.definition.list+json',
                'Content-Type': 'application/vnd.vmware.horizon.manager.entitlements.v2.definition.list+json'}
    resp1 = requests.get(u, headers=headers3, verify=False)
    jsonresp1 = json.loads(resp1.content)
    mainapplist.append(trimjson)
    mainapplist.append(appId)
    mainapplist.append(jsonresp1)

print(mainapplist)







