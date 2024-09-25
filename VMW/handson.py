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
api_urlbase = "https://########.#######/SAAS/"
clid = "##############"
clsecret = "##############"
encodedtoken = get_encoded(clid, clsecret)
extra = "auth/oauthtoken"
headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
accesstoken = get_access_token(api_urlbase+extra,headers)
print(accesstoken)
users=[]
usersearchurl="https://#####.#######.com/SAAS/jersey/manager/api/scim/Users?filter=username%20eq%20%22gautamm%22"
headers2 = {'Content-Type' : 'application/json' , 'Authorization' : 'Bearer ' + accesstoken}
resp = requests.get(usersearchurl, headers=headers2,verify=False)
print("API call completed")
jsonresp = json.loads(resp.text)
#print(jsonresp)
tmpjsn = jsonresp.get("Resources")
#print(tmpjsn)

for i in tmpjsn:
    print(i['groups'])



"""tempjsn = jsonresp.get("Resources")"""