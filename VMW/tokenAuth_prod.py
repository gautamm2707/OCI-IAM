#!/usr/bin/env python

import logging
import requests
import getpass
import json
import base64
from optparse import OptionParser
import urllib3

urllib3.disable_warnings()
pSize = 500

from time import gmtime, strftime

dt = strftime("%Y%m%d", gmtime())

key = ""

color = {"True": "\033[32m", "False": "\033[31m", "warn": "\033[0;30;41m", "norm": "\033[0m"}


def getUserID(user):
    if options.verbose:
        print
        "Obtaining UserID for %s" % user
    header = {}
    header['Authorization'] = "%s" % key

    u = 'https://%s/SAAS/jersey/manager/api/scim/Users?filter=username eq "%s"' % (options.tenant, options.user)

    r = requests.request('GET', u, headers=header, verify=False)
    userInfo = r.json()

    if options.verbose:
        print
        "User info %s" % userInfo['Resources'][0]['id']

    return userInfo['Resources'][0]['id']


def tokenDel():
    header = {}
    header['Authorization'] = "%s" % key
    header['Content-Type'] = "application/vnd.vmware.horizon.manager.tokenauth.generation.request+json"
    header['Accept'] = "application/vnd.vmware.horizon.manager.tokenauth.link.response+json"

    u = "https://%s/SAAS/jersey/manager/api/token/auth/state/%s" % (options.tenant, getUserID(options.user))

    r = requests.request('DELETE', u, headers=header, verify=False)

    if r.status_code == 204:
        if options.verbose:
            print
            "Token successfully deleted for %s." % options.user
        return True
    else:
        if options.verbose:
            print
            "Token delete FAILED for %s." % options.user
        return False


def tokenReq():
    header = {}
    header['Authorization'] = "%s" % key
    header['Content-Type'] = "application/vnd.vmware.horizon.manager.tokenauth.generation.request+json"
    header['Accept'] = "application/vnd.vmware.horizon.manager.tokenauth.link.response+json"

    data = '{"domain" : "vmware.com","userName" : "%s"}' % options.user

    u = "https://%s/SAAS/jersey/manager/api/token/auth/state" % options.tenant

    if options.verbose:
        print
        "Requesting Token for %s." % options.user

    r = requests.request('POST', u, headers=header, data=data, verify=False)
    tokenlink = r.json()

    if 'loginLink' in tokenlink:
        return tokenlink['loginLink']
    else:
        return "Link Request Failed."


def getKey(secret):
    header = {}
    header['Authorization'] = "Basic %s" % secret
    header['Content-Type'] = "application/x-www-form-urlencoded"

    data = {'grant_type': 'client_credentials'}

    u = "https://%s/SAAS/auth/oauthtoken" % options.tenant

    r = requests.request('POST', u, headers=header, params=data, verify=False)
    token = r.json()['access_token']

    return "HZN %s" % token


def acquire_admin_token():
    username = raw_input("Admin username: ")
    password = getpass.getpass("Admin password: ")

    headers = {"content-type": "application/json", "accept": "application/json"}
    request_body = json.dumps({"username": username, "password": password, "issueToken": "true"})
    response = requests.post("https://%s/SAAS/API/1.0/REST/auth/system/login" % options.tenant, data=request_body,
                             headers=headers)

    if response.status_code != 200:
        logging.error("Could not acquire admin token: %s" % response.text)
        raise RuntimeError("login failed ({0}): {1}".format(response.status_code, response.text))
    admin_token = response.json()['sessionToken']
    return "Bearer %s" % admin_token


def main():
    global key

    usage = "usage: %prog [arg | -f filter] [options]"
    parser = OptionParser(usage)
    parser.add_option("-t", "--tenant", action="store", type="string", dest="tenant",
                      default="myvmware.workspaceair.com", help="Tenant to perform the snapshot on.")
    parser.add_option("-a", "--apiuser", action="store", type="string", dest="apiuser", default="rc_cli",
                      help="Use API user and key. Best for use in scripts.")
    parser.add_option("-k", "--apikey", action="store", type="string", dest="apikey",
                      default="Csc0wXfh4RrebtTZo5SFTRg5CIQiMO3tagHxGwburNqR3Q8m",
                      help="Use API key. Best for use in scripts.")
    parser.add_option("-l", "--login", action="store_true", dest="login", default=False,
                      help="Use manual login for one off dumps.")
    parser.add_option("-d", "--del", action="store_true", dest="tdel", default=False, help="Delete Token")
    parser.add_option("-r", "--req", action="store_true", dest="treq", default=False, help="Request Token")
    parser.add_option("-f", "--full", action="store_true", dest="tful", default=False,
                      help="Delete Token AND Request Token")
    parser.add_option("-u", "--user", action="store", type="string", dest="user", default="",
                      help="User to request or delete token for.")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                      help="Turn on verbose mode.")
    global options, args
    (options, args) = parser.parse_args()

    secret = base64.b64encode("%s:%s" % (options.apiuser, options.apikey))

    if options.user == "" or (options.tdel == False and options.treq == False and options.tful == False):
        print
        "Must include a user to operate with and select and action to perform."
        parser.print_help()
        exit()

    if options.apikey != "" and options.apiuser != "":
        if options.verbose:
            print("#####: Taking a snapshot of %s" % options.tenant)
        key = getKey(secret)
    else:
        tinput = raw_input("Press enter to use default or enter new tenant (%s):" % options.tenant)
        if tinput != "":
            options.tenant = tinput
        key = acquire_admin_token()

    if options.tful == False and options.treq == False and options.tdel == True and options.user != "":
        if options.verbose:
            print
            "Deleting Token for %s" % options.user
        tokenDel()
    elif options.tful == False and options.tdel == False and options.treq == True and options.user != "":
        if options.verbose:
            print
            "Requesting Token for %s" % options.user
        print
        "%s, %s" % (options.user, tokenReq())
    elif options.tful == True and options.tdel == False and options.treq == False and options.user != "":
        if options.verbose:
            print
            "Deleting Token and Requesting Token for %s" % options.user
        tokenDel()
        print
        "%s, %s" % (options.user, tokenReq())


if __name__ == "__main__":
    main()