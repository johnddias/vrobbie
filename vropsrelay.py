import json
import requests
import logging
import re
import sys
import time

token = ""
user = "admin"
passwd = "VMware1!"

def GetToken(user, passwd, host):
    if not token:
        url = "https://" + host + "/suite-api/api/auth/token/acquire"
        payload = "{\r\n  \"username\" : \"" + user + "\",\r\n  \"authSource\" : \"local\",\r\n  \"password\" : \"" + passwd + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
        response = requests.request("POST", url, data=payload, headers=headers, verify=0)
        return response.text
    elif int(token["validity"])/1000 < time.time():
        url = "https://" + host + "/suite-api/api/versions"
        headers = {
            'authorization': "vRealizeOpsToken " + token["token"],
            'accept': "application/json"
        }
        response = requests.request("GET", url, headers=headers, verify=0)
        if response.status_code == 401:
            url = "https://" + host + "/suite-api/api/auth/token/acquire"
            payload = "{\r\n  \"username\" : \"" + user + "\",\r\n  \"authSource\" : \"local\",\r\n  \"password\" : \"" + passwd + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
            headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
            response = requests.request("POST", url, data=payload, headers=headers, verify=0)
            return response.text
        else:
            return json.dumps(token)
    else:
        return json.dumps(token)

def GetResourceStatus(name,host):
    global token
    token = json.loads(GetToken(user, passwd, host))
    url = "https://" + host + "/suite-api/api/resources"

    querystring = {"name": name}

    headers = {
        'authorization': "vRealizeOpsToken " + token["token"],
        'accept': "application/json",
        }

    response = requests.request("GET", url, headers=headers, params=querystring, verify=0)
    response_parsed = json.loads(response.text)
    print response_parsed
    return response_parsed

def GetActiveAlerts(badge,reskind,host):
    global token
    token = json.loads(GetToken(user,passwd,host))
    url = "https://" + host + "/suite-api/api/alerts/query"

    headers = {
        'authorization': "vRealizeOpsToken " + token["token"],
        'accept': "application/json",
        'content-type': "application/json"
    }

    querypayload = {
        'resource-query': {
            'resourceKind': [reskind]
        },
        'activeOnly': True,
        'alertCriticality': ["CRITICAL","IMMEDIATE","WARNING","INFORMATION"],
        'alertImpact': [badge]
    }
    print querypayload
    response = requests.request("POST", url, headers=headers, json=querypayload, verify=0)
    response_parsed = json.loads(response.text)
    return response_parsed
