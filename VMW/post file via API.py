import requests
import base64

apiurl = 'https://######.com/intranet/api/ws1-index/?type=user'
username = "#######"
password = "ws1@#######"

basicAuth = username+":"+password
basicAuth = basicAuth.encode('ascii')
basicAuth = base64.b64encode(basicAuth)
basicAuth = basicAuth.decode('ascii')
headers = {'X-Authorization': 'Basic '+basicAuth}

zipname = "users.zip"

fin = open(zipname, 'rb')
files = {'file': fin}

try:
  r = requests.post(apiurl, files=files, headers=headers, verify=False)
  print(r.text)
finally:
	fin.close()
