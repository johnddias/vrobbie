#!/usr/bin/python

import json
import logging
import requests
import time
import re
import sys
import os

from flask import Flask, render_template
from flask_ask import Ask, statement, question, session

# Vars and Configurations

bearertoken = ""
# Edit with IP or FQDN of vrops node
vropsHost = ""
# Authentication is intially via credentials set.  Subsequent calls use a
# bearer token.
vropsuser = ""
vropspassword = ""
vropsauthsource = "local"
# For some labs, using self-signed will result in error during request due to cert check
# flip this flag to False to bypass certificate checking in those cases
verify = False

app = Flask(__name__)
ask = Ask(app,"/")
logging.getLogger("flask_ask").setLevel(logging.DEBUG)

##############################################
# HELPERS
# - Fetchers
# - Handling voice service errors
# - Parsing and preparing response_msg
##############################################

def vropsGetToken(user=vropsuser, passwd=vropspassword, authSource=vropsauthsource, host=vropsHost):
    if not bearertoken:
        url = "https://" + host + "/suite-api/api/auth/token/acquire"
        payload = "{\r\n  \"username\" : \"" + vropsuser + "\",\r\n  \"authSource\" : \"" + authSource + "\",\r\n  \"password\" : \"" + vropspassword + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
        response = requests.request("POST", url, data=payload, headers=headers, verify=verify)
        return response.text
    elif int(bearertoken["validity"])/1000 < time.time():
        url = "https://" + host + "/suite-api/api/versions"
        headers = {
            'authorization': "vRealizeOpsToken " + bearertoken["token"],
            'accept': "application/json"
        }
        response = requests.request("GET", url, headers=headers, verify=verify)
        if response.status_code == 401:
            url = "https://" + host + "/suite-api/api/auth/token/acquire"
            payload = "{\r\n  \"username\" : \"" + vropsuser + "\",\r\n  \"authSource\" : \"" + vroauthsource + "\",\r\n  \"password\" : \"" + vropspassword + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
            headers = {
            'accept': "application/json",
            'content-type': "application/json",
            }
            response = requests.request("POST", url, data=payload, headers=headers, verify=verify)
            return response.text
        else:
            return json.dumps(bearertoken)
    else:
        return json.dumps(bearertoken)

def vropsRequest(request,method,querystring="",payload=""):
    global bearertoken
    bearertoken = json.loads(vropsGetToken())

    url = "https://" + vropsHost + "/suite-api/" + request
    querystring = querystring
    headers = {
        'authorization': "vRealizeOpsToken " + bearertoken["token"],
        'accept': "application/json",
        'content-type': "application/json"
    }
    if (querystring != "") and (payload != ""):
        response = requests.request(method, url, headers=headers, params=querystring, json=payload, verify=verify)
    elif (querystring != ""):
        response = requests.request(method, url, headers=headers, params=querystring, verify=verify)
    elif (payload != ""):
        response = requests.request(method, url, headers=headers, json=payload, verify=verify)
    else:
        response = requests.request(method, url, headers=headers, verify=verify)

    print ("Request " + response.url + " returned status " + str(response.status_code))
    return response.json()

def translate_resource_intent(resource):
    print("Stated intent " + resource)
    resString = ""
    vropsResKindString = {
        'bms':'virtualmachine',
        'vms':'virtualmachine',
        'hosts': 'hostsystem',
        'clusters': 'clustercomputeresource',
        'datastores': 'datastore'
    }
#    if intent['slots']['resource']['value'] in vropsResKindString:
    resString = vropsResKindString.get(resource.lower())
    return resString

def speechify_resource_intent(resource,plurality):
        vocalString = ""
        vocalStrings = {
            'bms':'virtual machine',
            'vms':'virtual machine',
            'hosts': 'host system',
            'clusters': 'cluster',
            'datastores': 'data store'
        }
        if plurality:
            vocalString = vocalStrings.get(resource.lower()) + "s"
        else:
            vocalString = vocalStrings.get(resource.lower())
        return vocalString

def alerts_by_sev(alerts,sev):
    filteredAlerts = []
    if any(x == sev for x in ["INFO","WARNING","IMMEDIATE","CRITICAL"]):
        for alert in alerts["alerts"]:
            if alert["alertLevel"] == sev:
                filteredAlerts.append(alert)
    return filteredAlerts

def group_alerts(alerts):
    groupedAlerts = []
    groupedAlerts = Counter(alerts)
    return groupedAlerts

def sessionCleanup():
    if os.path.exists("sessionData/"+session.sessionId):
        os.remove("sessionData/"+session.sessionId)


#####################################################
# Invocations
#####################################################

@ask.launch

def welcome_msg():
    welcome_msg = render_template('welcome')
    return question(welcome_msg)

@ask.intent('AMAZON.YesIntent')

def continues():
    if session.attributes["CurrentTree"] == "Alerts":
        with open("sessionData/"+session.sessionId, 'r') as alertsFile:
            alerts = ""
            alerts = json.load(alertsFile)
            criticalAlerts = alerts_by_sev(alerts,"CRITICAL")
            alert = criticalAlerts[session.attributes["AlertsIndex"]]
            alertDefinition = alert["alertDefinitionName"]
            resource = vropsRequest(alert["links"][1]["href"][10:] ,"GET")
            resourceName = resource["resourceKey"]["name"]
            outputSpeech = "The resource; {0}; has a critical alert, {1}.  Next alert or more information?".format(resourceName, alertDefinition)
            session.attributes["CurrentObject"] = resource["identifier"]
            session.attributes["AlertsIndex"] += 1
            return question(outputSpeech)
#    if session.attributes["CurrentTree"] == "Resource":

@ask.intent('MoreInformationIntent')

def more_info():
    if session.attributes["CurrentTree"] == "Alerts":
            session.attributes["CurrentTree"] = "Resource"
            resource = vropsRequest("api/resources/"+session.attributes["CurrentObject"],"GET")

            alertsQueryPayload = {
                        'resource-query': {
                            'resourceId': [session.attributes["CurrentObject"]]
                        },
                        'activeOnly': True
                }
            resourceAlerts = vropsRequest("api/alerts/query","POST",payload=alertsQueryPayload)

            resourceName = resource["resourceKey"]["name"]
            resourceHealth = resource["resourceHealth"]
            resourceAlertCount = resourceAlerts["pageInfo"]["totalCount"]
            outputSpeech = "The resource; {0}; is; {1}; for health status.  There are {2} alerts associated with this resource.  Shall I read those alerts?".format(resourceName, resourceHealth, resourceAlertCount)
            return question(outputSpeech)



@ask.intent('HealthStatusIntent')

def health_status(badge, resource):
    request = "api/alerts/query"
    method = "POST"
    payload = {
            'resource-query': {
                'resourceKind': [translate_resource_intent(resource)]
            },
            'activeOnly': True,
            'alertCriticality': ["CRITICAL","IMMEDIATE","WARNING","INFORMATION"],
            'alertImpact': [badge]
    }

    alerts = vropsRequest(request,method,payload=payload)

    numAllAlerts = str(alerts["pageInfo"]["totalCount"])
    numImmediateAlerts = str(len(alerts_by_sev(alerts,"IMMEDIATE")))
    numCriticalAlerts = str(len(alerts_by_sev(alerts,"CRITICAL")))

    speech_output = "There are " + numAllAlerts + " " + badge + " alerts for monitored " + speechify_resource_intent(resource,1) + ". "  + \
                     "Of those " + numCriticalAlerts + " are critical and " + numImmediateAlerts + " are immediate.  Shall I read the critical alerts?"

    with open("sessionData/"+session.sessionId, 'w') as outfile:
        json.dump(alerts, outfile)
    session.attributes["AlertsIndex"] = 0
    session.attributes["CurrentTree"] = "Alerts"

    return question(speech_output)

@ask.intent('getAlertsIntent')

@ask.intent('getOverallStatus')

@ask.intent('goodbyeIntent')

def goodbye_msg():
    goodbye_msg = render_template('goodbye')
    logging.debug("Session Ended")
    sessionCleanup()
    return statement(goodbye_msg)


@ask.session_ended

def session_ended():
    logging.debug("Session Ended")
    sessionCleanup()
    return "", 200

if __name__ == '__main__':
    app.run(debug=True)
