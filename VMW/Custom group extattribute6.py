import json
import requests
import base64

def get_encoded(clid, clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded
def get_access_token(url,header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter,verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token
api_urlbase = "https://ws-cet-vidm1.vmware.com/SAAS/"
clid = "abhi-client"
clsecret = "8vQ95VjRcOua7om7wPgyPbgiE4jRbF6hyoilnFurP1ljhNIi"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra,headers)
groups=[]
groupsearchurl="https://ws-cet-vidm1.vmware.com/SAAS/jersey/manager/api/scim/Groups?sortBy=displayName&filter=domain eq \"System Domain\"&startIndex=0&pageSize=500"
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
print(groups)
