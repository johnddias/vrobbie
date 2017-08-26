#!/usr/bin/python

import json
import logging
import requests
import collections
import time
import re
import sys
import os
from threading import Thread
from operator import itemgetter
from itertools import groupby
from flask import Flask, render_template
from flask_ask import Ask, statement, question, session, request, context, version

# Vars and Configurations
bearertoken = ""

# Edit with IP or FQDN of vrops and LI node
vropsHost = "10.140.50.30"
liHost = "10.140.44.20"
# Authentication is intially via credentials set.  Subsequent calls use a
# bearer token.
vropsuser = "admin"
vropspassword = "VMware1!"
vropsauthsource = "local"
liprovider = "ActiveDirectory"
liusername = "diasj"
lipassword = "VMware1!"
# For some labs, using self-signed will result in error during request due to cert check
# flip this flag to False to bypass certificate checking in those cases.  I have suppressed the warning
# normally thrown by urllib3 but this is NOT RECOMMENDED!
verify = False
if not verify:
    requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
ask = Ask(app,"/")
logging.getLogger("flask_ask").setLevel(logging.DEBUG)

##############################################
# HELPERS
# - Fetchers
# - Handling voice service errors
# - Parsing and preparing response_msg
##############################################
def datacenter_report():
    while True:
        dc_report_dict = dict()
        token = json.loads(liGetToken(liusername, lipassword, liprovider))
        dc_report_dict["vMotions"] = json.loads(loginsightQuery("timestamp/LAST 86400000", "bin-width=all&aggregation-function=UCOUNT&aggregation-field=com.vmware.vsphere:vmw_hostd_vmotion_id", token["sessionId"]))
        dc_report_dict["DRS vMotions"] = json.loads(loginsightQuery("timestamp/LAST 86400000/text/CONTAINS DrmExecuteVMotionLRO", "bin-width=all&aggregation-function=COUNT", token["sessionId"]))
        dc_report_dict["VMs Created"] = json.loads(loginsightQuery("timestamp/LAST 86400000/vc_event_type/CONTAINS com.vmware.vim25.VmCreatedEvent/vc_event_type/CONTAINS com.vmware.vim25.vmclonedevent", "bin-width=all&aggregation-function=COUNT", token["sessionId"]))
        dc_report_dict["VMs Deleted"] = json.loads(loginsightQuery("timestamp/LAST 86400000/vc_event_type/CONTAINS com.vmware.vim25.VmRemovedEvent", "bin-width=all&aggregation-function=COUNT", token["sessionId"]))
        dc_report_dict["RConsole Sessions"] = json.loads(loginsightQuery("timestamp/LAST 86400000/text/CONTAINS Local connection for mks established", "bin-width=all&aggregation-function=COUNT", token["sessionId"]))

        with open("prefetch/dcreport", 'w') as outfile:
            json.dump(dc_report_dict, outfile)

        print "dcreport updated at " + time.strftime("%Y-%m-%d %H:%M:%S")
        time.sleep(300)

def more_info():
    #Called when user wants more information on the impacted resource from the Alerts tree
    if session.attributes["CurrentTree"] == "Alerts":

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

            with open("sessionData/"+session.sessionId+"resAlerts", 'w') as outfile:
                json.dump(resourceAlerts, outfile)
            session.attributes["ResAlertsIndex"] = 0
            session.attributes["CurrentTree"] = "Resource"

            return outputSpeech

    #Called when user wants more information on an alert from the Resource tree
    if session.attributes["CurrentTree"] == "Resource":
            alert = vropsRequest("api/alerts/"+session.attributes["CurrentAlert"],"GET")
            alertDef = vropsRequest("api/alertdefinitions/"+alert["alertDefinitionId"],"GET")
            alertDesc = alertDef["description"]
            recommendations=alertDef["states"][0]["recommendationPriorityMap"]
            if (len(recommendations) == 1):
                recQualifier = "only"
            else:
                recQualifier = "first"
            recDesc = vropsRequest("api/recommendations/"+recommendations.keys()[0],"GET")

            outputSpeech = "{0}.  The {1} recommendation is as follows; {2}".format(alertDesc, recQualifier, recDesc["description"])
            return outputSpeech

    #Called when user wants more information on groups of alerts for a definition
    if session.attributes["CurrentTree"] == "GroupedAlerts":
            payload = json.loads('{"resourceId":'+ json.dumps(session.attributes["impactedResources"]) +'}')
            resources = vropsRequest("api/resources/query","POST",payload=payload)
            resourceList = resources["resourceList"]
            resourceDict = {}
            for res in resourceList:
                resourceDict[res["resourceKey"]["name"]] = res["identifier"]
            session.attributes["resourceDict"] = resourceDict
            outputSpeech = ""
            return outputSpeech

def continues():
    if session.attributes["CurrentTree"] == "Alerts":
        with open("sessionData/"+session.sessionId+"badgeAlerts", 'r') as alertsFile:
            alerts = ""
            alerts = json.load(alertsFile)
            criticalAlerts = alerts_by_sev(alerts,"CRITICAL")
            alert = criticalAlerts[session.attributes["AlertsIndex"]]
            alertDefinition = alert["alertDefinitionName"]
            resource = vropsRequest(alert["links"][1]["href"][10:] ,"GET")
            resourceName = resource["resourceKey"]["name"]
            if (len(criticalAlerts)-1 == session.attributes["AlertsIndex"]):
                outputSpeech = "The resource; {0}; has a critical alert, {1}.  There are no more cirtical alerts.  Would you like more information on this resource?".format(resourceName, alertDefinition)
            else:
                outputSpeech = "The resource; {0}; has a critical alert, {1}.  Next alert or more information on this resource?".format(resourceName, alertDefinition)
                session.attributes["AlertsIndex"] += 1

            session.attributes["CurrentObject"] = resource["identifier"]

            return outputSpeech

    if session.attributes["CurrentTree"] == "GroupedAlerts":
        with open("sessionData/"+session.sessionId+"groupAlerts", 'r') as alertsFile:
            alerts = ""
            alerts = json.load(alertsFile)
            definition = alerts[session.attributes["AlertsIndex"]]
            alertDefinition = definition[0]["alertDefinitionName"]
            impactedResources = []
            for res in definition:
                impactedResources.append(res["resourceId"])

            session.attributes["impactedResources"] = impactedResources
            session.attributes["alertDefinition"] = alertDefinition

            numOfResources = len(definition)
            if numOfResources == 1:
                resourceText = "resource is"
            else:
                resourceText = "resources are"

            if (len(alerts)-1 == session.attributes["AlertsIndex"]):
                outputSpeech = "For the alert: {0}, {1} {2} impacted.  There are no more alerts.  More information on this alert?".format(alertDefinition, numOfResources, resourceText)
            else:
                outputSpeech = "For the alert: {0}, {1} {2} impacted. Next or more info?".format(alertDefinition, numOfResources, resourceText)
                session.attributes["AlertsIndex"] += 1

            return outputSpeech

    if session.attributes["CurrentTree"] == "Resource":
        with open("sessionData/"+session.sessionId+"resAlerts", 'r') as alertsFile:
            alerts = ""
            alerts = json.load(alertsFile)
            criticalAlerts = alerts_by_sev(alerts,"CRITICAL")
            alert = criticalAlerts[session.attributes["ResAlertsIndex"]]
            alertDefinition = alert["alertDefinitionName"]
            resource = vropsRequest(alert["links"][1]["href"][10:] ,"GET")
            resourceName = resource["resourceKey"]["name"]
            if (len(criticalAlerts)-1 == session.attributes["ResAlertsIndex"]):
                outputSpeech = "The resource; {0}; has a critical alert, {1}.  There are no more alerts.  Would you like more information on this alert?".format(resourceName, alertDefinition)
            elif len(criticalAlerts) == 0:
                outputSpeech = "Reading active alerts from newest to oldest.  The resource; {0}; has a critical alert, {1}.  Next alert or more information on this alert?".format(resourceName, alertDefinition)
                session.attributes["ResAlertsIndex"] += 1
            else:
                outputSpeech = "The resource; {0}; has a critical alert, {1}.  Next alert or more information on this alert?".format(resourceName, alertDefinition)
                session.attributes["ResAlertsIndex"] += 1

            session.attributes["CurrentAlert"] = alert["alertId"]

            return outputSpeech

def on_element_select(token):
    if session.attributes["CurrentTree"] == "GroupedAlerts":
        resource = vropsRequest("api/resources/"+token,"GET")
        resourceProps = vropsRequest("api/resources/"+token+"/properties","GET")
        resourceLatest = vropsRequest("api/resources/"+token+"/stats/latest","GET")
        if resource["resourceKey"]["resourceKindKey"] == "VirtualMachine":
            #Build complete response Here
            vmname = resource["resourceKey"]["name"]
            guestOS = [d["value"] for d in resourceProps["property"] if d["name"]=="config|guestFullName"][0]
            numCpu = [d["value"] for d in resourceProps["property"] if d["name"]=="config|hardware|numCpu"][0]
            memKB = [d["value"] for d in resourceProps["property"] if d["name"]=="config|hardware|memoryKB"][0]
            toolsStatus = [d["value"] for d in resourceProps["property"] if d["name"]=="summary|guest|toolsRunningStatus"][0]
            toolsVersion = [d["value"] for d in resourceProps["property"] if d["name"]=="summary|guest|toolsVersion"][0]
            #guestDiskPercent = [d["statKey"]["data"] for d in resourceLatest["values"]["stat-list"]["stat"] if d["statKey"]["key"]=="guestfilesystem|percentage_total"]

        text = {
            "secondaryText": {
                "type": "RichText",
                "text": "<br/><b>Number of vCPU: </b>" + numCpu + "<br/>" + \
                        "<b>Memory Allocation (KB): </b>" + memKB + "<br/>" + \
                        "<b>Guest OS Name: </b>" + guestOS + "<br/>" + \
                        "<b>Tools Status: </b>" + toolsStatus + "<br/>" + \
                        "<b>Tools Version: </b>" + toolsVersion + "<br/>"
                        #"<b>Guest Filesystem Used: </b>" + guestDiskPercent + "%%<br/>"
            },
            "primaryText": {
                "type": "RichText",
                "text": "<font size='3'>"+resource["resourceKey"]["name"]+"</font>"
            }
        }

        fullResponse = question("Here are the " + resource["resourceKey"]["resourceKindKey"] + " details"). \
        display_render(title=resource["resourceKey"]["resourceKindKey"] + "details",template="BodyTemplate1",text=text,background_image_url=render_template('backgroundImageURL'),backButton='VISIBILE')
        return fullResponse

def backout():
    if session.attributes["CurrentTree"] == "Resource":
        session.attributes["CurrentTree"] = "Alerts"
        outputSpeech = "Returning to Critical Alerts list."
    elif session.attributes["CurrentTree"] == "GroupedAlerts":
        session.attributes["CurrentTree"] = ""
        outputSpeech = "I am waiting for your query"
    elif session.attributes["CurrentTree"] == "Alerts":
        sessionCleanup()
        session.attributes["CurrentTree"] = ""
        outputSpeech = "I am waiting for your query"
    else:
        sessionCleanup()
        outputSpeech = "I am waiting for your query"
    return outputSpeech

def interactive_resp(data):
    if session.attributes["CurrentTree"] == "GroupedAlerts":
        listItems = []
        resDict = session.attributes["resourceDict"]
        for res in resDict:
            listItem = {
                "token":resDict[res],
                "textContent": {
                    "primaryText": {
                        "text":res,
                        "type":"PlainText"
                    }
                }
            }
            listItems.append(listItem)


    enhancedResponse = question("Here are the impacted objects.").list_display_render(template="ListTemplate1", title="Impacted Objects", backButton="VISIBILE", token=None, \
    background_image_url=render_template('backgroundImageURL'), listItems=listItems)

    return enhancedResponse

def liGetToken(user=liusername, passwd=lipassword, authSource=liprovider):
        url = "https://" + liHost + "/api/v1/sessions"
        payload = "{\n  \"provider\":\"" + liprovider + "\",\n  \"username\":\"" + liusername + "\",\n  \"password\":\"" + lipassword + "\"\n}"
        headers = {
            'accept': "application/json",
            'content-type': "application/json"
            }
        response = requests.request("POST", url, data=payload, headers=headers, verify=verify)

        return response.text

def vropsGetToken(user=vropsuser, passwd=vropspassword, authSource=vropsauthsource, host=vropsHost):
    if not bearertoken:
        url = "https://" + host + "/suite-api/api/auth/token/acquire"
        payload = "{\r\n  \"username\" : \"" + vropsuser + "\",\r\n  \"authSource\" : \"" + vropsauthsource + "\",\r\n  \"password\" : \"" + vropspassword + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
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
            payload = "{\r\n  \"username\" : \"" + vropsuser + "\",\r\n  \"authSource\" : \"" + vropsauthsource + "\",\r\n  \"password\" : \"" + vropspassword + "\",\r\n  \"others\" : [ ],\r\n  \"otherAttributes\" : {\r\n  }\r\n}"
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

def loginsightQuery(constraints,params,token):
    url = "https://" + liHost + "/api/v1/aggregated-events/" + constraints + "?" + params
    headers = {
        'authorization': 'Bearer ' +  token
    }
    response = requests.request('GET', url, headers=headers, verify=verify)

    return response.text


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
    print payload
    return response.json()

def translate_resource_intent(resource):
    resString = ""
    vropsResKindString = {
        'bms':'virtualmachine',
        'bm':'virtualmachine',
        'vms':'virtualmachine',
        'vm':'virtualmachine',
        'hosts': 'hostsystem',
        'host': 'hostsystem',
        'clusters': 'clustercomputeresource',
        'cluster': 'clustercomputeresource',
        'datastores': 'datastore',
        'datastore': 'datastore'
    }
#    if intent['slots']['resource']['value'] in vropsResKindString:
    resString = vropsResKindString.get(resource.lower())
    return resString

def speechify_resource_intent(resource,plurality):
        vocalString = ""
        vocalStrings = {
            'bm':'virtual machine',
            'vm':'virtual machine',
            'host': 'host system',
            'cluster': 'cluster',
            'datastore': 'data store',
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

def group_alerts_by_def(alerts,groupkey):
    sortedAlerts = sorted(alerts, key=itemgetter(groupkey))
    groupedAlerts = []
    for key, items in groupby(sortedAlerts, itemgetter(groupkey)):
        groupedAlerts.append(list(items))
    return groupedAlerts

def sessionCleanup():
    dir = "sessionData"
    files = os.listdir(dir)
    for file in files:
        if file.startswith(session.sessionId):
            os.remove(os.path.join(dir,file))

#####################################################
# Invocations
#####################################################

@ask.launch

def welcome_msg():
    welcome_msg = render_template('welcome')
    textContent = {
        'primaryText': {
        'text':'<font size="3">Intelligent Operations</font>',
        'type':'RichText'
        }
    }
    if (context.System.device.supportedInterfaces.Display):
        return question(welcome_msg).display_render(
        title='Welcome to vRealize Operations',template="BodyTemplate2",text=textContent,background_image_url=render_template('backgroundImageURL'),image=render_template('vrops340x340ImageURL'), \
        hintText="Get Critical VM alerts")
    else:
        return question(welcome_msg)

@ask.intent('AMAZON.YesIntent')

def yesIntent():
    outputSpeech = continues()
    textContent = {
        'primaryText': {
        'text':"<font size='3'>"+outputSpeech+"</font>",
        'type':'RichText'
        }
    }
    title = 'Welcome to vRealize Operations'
    image = ""
    if (session.attributes["CurrentTree"] == "GroupedAlerts"):
        title = "Alerts by Definition"
        image = render_template('alert' + session.attributes['groupCriticality'] + 'ImageURL')

    if (context.System.device.supportedInterfaces.Display):
        return question(outputSpeech).display_render(
        title=title,template="BodyTemplate1",text=textContent,background_image_url=render_template('backgroundImageURL'),image=image)
    else:
        return question(outputSpeech)

@ask.intent('AMAZON.NextIntent')

def nextIntent():
    outputSpeech = continues()
    textContent = {
        'primaryText': {
        'text':"<font size='3'>"+outputSpeech+"</font>",
        'type':'RichText'
        }
    }
    title = 'Welcome to vRealize Operations'
    image = ""
    if (session.attributes["CurrentTree"] == "GroupedAlerts"):
        title = "Alerts by Definition"
        image = render_template('alert' + session.attributes['groupCriticality'] + 'ImageURL')

    if (context.System.device.supportedInterfaces.Display):
        return question(outputSpeech).display_render(
        title=title,template="BodyTemplate2",text=textContent,background_image_url=render_template('backgroundImageURL'),image=image)
    else:
        return question(outputSpeech)

@ask.intent('MoreInformationIntent')

def MoreInformationIntent():
    outputSpeech = more_info()
    textContent = {
        'primaryText': {
        'text':outputSpeech,
        'type':'PlainText'
        }
    }
    if ((session.attributes["CurrentTree"] == "GroupedAlerts") and (context.System.device.supportedInterfaces.Display)):
        enhancedResponse = interactive_resp(outputSpeech)
        return enhancedResponse
    elif (context.System.device.supportedInterfaces.Display):
        return question(outputSpeech).display_render(
        title='Welcome to vRealize Operations',template="BodyTemplate2",text=textContent,background_image_url=render_template('backgroundImageURL'))
    else:
        if (session.attributes["CurrentTree"]):
            return question(outputSpeech)
        else:
            return question("I'm sorry, I don't understand your request")


@ask.intent('AMAZON.NoIntent')

def noIntent():
    outputSpeech = backout()
    textContent = {
    'primaryText': {
        'text':'Intelligent Operations',
        'type':'PlainText'
        }
    }
    if (context.System.device.supportedInterfaces.Display):
        return question(outputSpeech).display_render(
        title='Welcome to vRealize Operations',template="BodyTemplate2",text=textContent,background_image_url=render_template('backgroundImageURL'))
    else:
        return question(outputSpeech)

@ask.intent('Amazon.CancelIntent')

def cancelIntent():
    outputSpeech = backout()
    return question(outputSpeech)

@ask.intent('vSANStatusIntent')
def vsanstatus():
#build query Parameters
    vsanworld_res = vropsRequest("api/resources","GET",querystring="resourceKind=vSAN World")
    vsan_res_id = vsanworld_res["resourceList"][0]["identifier"]
    begin = int(round(time.time()*1000-21600000))
    end = int(round(time.time()*1000))
    querystring = {"begin":begin,"end":end,"rollUpType":"AVG","intervalQuantifier":"7", \
        "intervalType":"HOURS",\
        "statKey": [ "summary|total_latency", \
        "summary|total_iops", \
        "summary|total_number_vms", \
        "summary|total_cluster_count", \
        "summary|vsan_diskspace_capacity", \
        "summary|vsan_diskspace_capacity_used", \
        "summary|remaining_capacity" ], \
        "resourceId":vsan_res_id, }
#execute query and process
    response = vropsRequest("api/resources/stats","GET",querystring)

#building response
    stats_dict = dict()
    for statitem in response["values"][0]["stat-list"]["stat"]:
        stat_key = statitem["statKey"]["key"].split("|")[1].replace("_"," ").title()
        if (stat_key.find("Cluster Count") != -1):
            stat_key = "Number of Clusters"
        if (stat_key.find("Capacity") != -1):
            stat_key = stat_key + " in TB"
        if (stat_key.find("Vsan") != -1):
            stat_key = stat_key.replace("Vsan","")
        if (stat_key.find("Total") != -1):
            stat_key = stat_key.replace("Total","Average")
        if (stat_key.find("Iops") != -1):
            stat_key = stat_key.replace("Iops","IOPS")
        if (stat_key.find("Vms") != -1):
            stat_key = stat_key.replace("Vms","of VMs")
            stat_key = stat_key.replace("Average","")
        stats_dict[stat_key] = str(int(statitem["data"][0]))

#TODO add ordering to display so items appear in some logical ordering

    secondaryText = "<br/>"
    for key, value in sorted(stats_dict.iteritems(), key=lambda (k,v): (v,k)):
        secondaryText = secondaryText + "<b> %s:</b> %s <br/>" %(key,value)
    secondaryText = secondaryText + "<br/>"

    text = {
        "tertiaryText": {
            "type":"RichText",
            "text":"6 hour average statistics shown."
        },
        "secondaryText": {
            "type": "RichText",
            "text": secondaryText
        },
        "primaryText": {
            "type": "RichText",
            "text": "<b><font size='7'>vSAN Status</font></b>"
        }
    }

    enhancedResponse = question("v SAN Status Report.").display_render(template="BodyTemplate2", title="Datacenter Operations", text=text,backButton="VISIBILE", token=None, \
    background_image_url=render_template('backgroundImageURL'),image=render_template('vsan340x340ImageURL'))

    return enhancedResponse

@ask.intent('DataCenterCapacityIntent')
def dccapacity():
    return question("Data Center Capacity Report")

@ask.intent('DataCenterActivityIntent')
#Runs several Log Insight and vROps queries to build a report for echo show
#TODO Make sure to add device checking and optimize for echo voice only
def dcactivity():
    secondaryText = "<br/>"
    with open("prefetch/dcreport", 'r') as dcreport:
        report_data = json.load(dcreport)
        for metric, value in report_data.iteritems():
            item = "<b>Number of " + metric + ": </b>"
            if not (value["bins"]):
                item = item + "None"
            else:
                item = item + str(value["bins"][0]["value"])
            secondaryText = secondaryText + item + "<br/>"

    text = {
        "secondaryText": {
            "type": "RichText",
            "text": secondaryText
        },
        "primaryText": {
            "type": "RichText",
            "text": "<font size='5'>Datacenter Activity Past 24 Hours</font>"
        }
    }

    enhancedResponse = question("Datacenter Activity in the Past 24 Hours.").display_render(template="BodyTemplate2", title="Datacenter Operations", text=text,backButton="VISIBILE", token=None, \
    background_image_url=render_template('backgroundImageURL'), image=render_template('vsphere340x340ImageURL'))

    return enhancedResponse

@ask.intent('GroupAlertsIntent')
#Starts a tree to read active alerts grouped by alert definition for the stated resource kind
#and criticality.  Alert definitions are read by group with option list individual alerts in a group
def group_criticality_alerts(criticality, resource):
    request = "api/alerts/query"
    method  = "POST"
    payload = {
        'resource-query': {
            'resourceKind': [translate_resource_intent(resource)]
        },
        'activeOnly': True,
        'alertCriticality': [criticality.upper()]
    }
    session.attributes["groupCriticality"] = criticality
    alerts = vropsRequest(request,method,payload=payload)

    numAllAlerts = str(alerts["pageInfo"]["totalCount"])

    speech_output = "There are " + numAllAlerts + " " + criticality + " alerts for monitored " + speechify_resource_intent(resource,1) + ". " + \
                    "Shall I read the alerts by alert definition?"
    textContent = {
            'primaryText': {
            'text': "<font size='7'>" + speech_output + "</font>",
            'type':'RichText'
            }
    }
    groupedAlerts = []
    groupedAlerts = group_alerts_by_def(alerts['alerts'],'alertDefinitionId')

    with open("sessionData/"+session.sessionId+"groupAlerts", 'w') as outfile:
        json.dump(groupedAlerts, outfile)

    session.attributes["AlertsIndex"] = 0
    session.attributes["CurrentTree"] = "GroupedAlerts"
    title = "Total " + criticality + " alerts for " + speechify_resource_intent(resource,1) + "."
    return question(speech_output).display_render(
    title=title,template="BodyTemplate1",text=textContent,background_image_url=render_template('backgroundImageURL',image="alertcriticalImageURL"))

@ask.intent('ListBadgeAlertsIntent')
#Starts a tree to read active alerts for the stated resource kind for a major badge.
#Alerts are read individually with option for more info depth for a resource
def list_badge_alerts(badge, resource):
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
    textContent = {
            'primaryText': {
            'text': "<font size='3'>" + speech_output + "</font>",
            'type':'RichText'
            }
    }
    with open("sessionData/"+session.sessionId+"badgeAlerts", 'w') as outfile:
        json.dump(alerts, outfile)
    session.attributes["AlertsIndex"] = 0
    session.attributes["CurrentTree"] = "Alerts"

    if (context.System.device.supportedInterfaces.Display):
        return question(speech_output).display_render(
        title='Welcome to vRealize Operations',text=textContent,background_image_url=render_template('backgroundImageURL'))
    else:
        return question(speech_output)

@ask.display_element_selected

def element():
    fullResponse = on_element_select(request["token"])
    return fullResponse

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
    bearertoken = json.loads(vropsGetToken())
    background_thread = Thread(target=datacenter_report)
    background_thread.daemon = True
    background_thread.start()
    app.run(debug=True)
