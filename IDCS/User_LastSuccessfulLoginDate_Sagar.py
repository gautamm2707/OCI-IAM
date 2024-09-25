
"""Written for obtaining list of usernames and LastLogin details and send it to CSV"""

import json
import requests
import base64
import urllib3
import xlwt
import ExcelpandasWork as pd
from zipfile import ZipFile
import shutil
from pathlib import Path
#import openpyxl as xl
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'


def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded
"""parameter = {"grant_type": "client_credentials", "scope":"urn:opc:idm:__myscopes__"}"""
def get_access_token(url,header):

    para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    response = requests.post(url, headers=header,data=para, verify=False)
    print(response.json)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

api_urlbase = "https://idcs-#############.identity.oraclecloud.com"
clid = "################"
clsecret = "7#################"
encodedtoken = get_encoded(clid, clsecret)
#print (encodedtoken)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
print (headers)
print (api_urlbase+extra)
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Getting Total count of users

searchurl = "https://idcs-##################.identity.oraclecloud.com/admin/v1/Users"
headers2 = {'Authorization': 'Bearer ' + accesstoken}
#headers2 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
#param = {'attributes': "Username,groups,emails"}
resp = requests.get(searchurl, headers=headers2, verify=False)
jsonresp = json.loads(resp.content)
totalCount = jsonresp.get("totalResults")
print(totalCount)

#Getting inactive users list

"""workbook = xlwt.Workbook()
sheet1 = workbook.add_sheet('Sheet 1')"""
"""new_wb = xl.Workbook()
sheet = new_wb.active"""
startIndex = 1
count = 50
loop = int(totalCount / count)
f_count = 0
mainlist = []
user_del_url = "https://idcs-3###############.identity.oraclecloud.com/admin/v1/Users/"
mainlist = []
for i in range(loop+1):
    param = {'attributes': "username,urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User:lastSuccessfulLoginDate", 'startIndex': startIndex, 'count': count}
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    startIndex += count
    jsonresp = json.loads(resp.content)
    """df = pd.Dataframe(jsonresp)
    df.to_excel('./SimData/exported_json_data.xlsx')"""
    tempjsn = jsonresp.get("Resources")
    for x in tempjsn:
        trimjsn = {}
        username = trimjsn['userName'] = x.get("userName")
        lastLoginDate = trimjsn['LastLogin'] = x.get("urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User")
        """lastLoginDate = str(x["urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"]["lastSuccessfulLoginDate"])"""
        print(username)
        print(lastLoginDate)
        mainlist.append(trimjsn)
    print(mainlist)
#for i in range(1, int(totalCount)):
#    sheet.cell(row=i, column=0).value = mainlist[0][0]
#    sheet.cell(row=i, column=1).value = mainlist[0][1]
#    i += 1
df_mainlist = pd.DataFrame(mainlist)
#new_wb.save(filename=r"C:\Users\gautmish\Downloads\NewExcel.xlsx")
print(df_mainlist)
df_mainlist.to_csv('mainlist.csv')

"""
# JSON dump
with open("LastLogin.json", "w") as outfile:
        json.dump(mainlist, outfile)
"""


