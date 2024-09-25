import json
import logging

# OAuth stuff
import requests
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import urllib.parse


# # debug HTTP
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 2

class IAMClient:

    def __init__(self):
        config = json.load(open('config.json'))
        global idcsURL
        global clientID
        global clientSecret

        idcsURL = config["iamurl"]
        clientID = config["client_id"]
        clientSecret = config["client_secret"]

        auth = HTTPBasicAuth(clientID, clientSecret)
        client = BackendApplicationClient(client_id=clientID)
        self.oauthClient = OAuth2Session(client=client)

        token = self.oauthClient.fetch_token(token_url=idcsURL + '/oauth2/v1/token',
                                             auth=auth,
                                             scope=["urn:opc:idm:__myscopes__"])
        logging.debug("Access Token: {}".format(token.get("access_token")))
        return token

obj = IAMClient()
obj.__init__()

