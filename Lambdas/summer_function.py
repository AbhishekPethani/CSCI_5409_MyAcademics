import json
from ast import parse
import csv
from fileinput import filename
from urllib import response
import boto3
import decimal
from botocore.exceptions import ClientError
import time
from botocore.vendored import requests 
session = boto3.Session()

dynamodb = session.resource('dynamodb')
SubjectCode = ''
SubjectSeats = ''
seatList = []
dictSubject = ''
subjectDictionary = {}
tempSubjectCode = ""
database_dict = {}
subjectNames = {}

def lambda_handler(event, context):
    tablename = "Summer_Courses"
    filename = "SummerCourses.csv"
    items = []
    read_database(tablename)
    getdata()
    compare_and_update(tablename)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

#https://www.youtube.com/watch?v=MOaXGYgqipQ <-- Reference Video

def read_database(tablename):
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(tablename)
    response = table.scan()

    for i in response['Items']:
        database_dict[str(i['CRN'])] = str(i['Seats'])
        subjectNames[str(i['CRN'])] = str(i['CourseName'])
    print(database_dict)
    print(subjectNames)

def getdata():
    try:
        # summer : https://dalonline.dal.ca/PROD/fysktime.P_DisplaySchedule?s_term=202230&s_crn=&s_subj=CSCI&s_numb=&n=21&s_district=100
        r = requests.get("https://dalonline.dal.ca/PROD/fysktime.P_DisplaySchedule?s_term=202230&s_crn=&s_subj=CSCI&s_numb=&n=21&s_district=100", stream=True)
        for line in r.iter_lines():
            s = line.decode("utf-8")
            CRN = '"<td CLASS="dettl"><b>"'
            if (s.startswith('<td CLASS="dettl"><b>') or s.startswith('<td CLASS="dettb"><b>') or s.startswith('<td CLASS="dettt"><b>') or s.startswith('<td CLASS="dettw"><b>')) and s[len(CRN)+1].isdigit():
                SubjectCode = s[len(CRN)-2:len(CRN)+3]
                subjectDictionary[SubjectCode] = ""
                tempSubjectCode = SubjectCode
                # print(SubjectCode)
            if  s.startswith('<font color='):
                if(s[-5:-1] != "font"):
                    subjectDictionary[tempSubjectCode] = s[-5:-1]
                else:
                    subjectDictionary[tempSubjectCode] = "100"
        print(subjectDictionary)

    except Exception as e:
        print(e)
        time.sleep(60)
        print("Sleeping for 60 secs")


def compare_and_update(tablename):
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(tablename)
    for key in database_dict:
        if(float(database_dict[key]) > float(subjectDictionary[key])):
            print("less than condition")
            invokeSNS(key)
            response = table.update_item(
                Key={
                    'CRN': int(key)
                },
                UpdateExpression="set Seats=:seats",
                ExpressionAttributeValues={
                    ':seats': subjectDictionary[key]
                },
                ReturnValues="UPDATED_NEW"
            )
        else:
            print("")

def invokeSNS(CRN):
    # TODO implement

    region_name = "us-east-1"

	# Creating a session
    session = boto3.Session(region_name = region_name)

	# Creating an sns session client
    client = session.client(
        service_name='sns',
        region_name=region_name
    )

	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.list_topics

    allTopics = client.list_topics()
    
    TopicPresent = False
    TopicArntosend = ""
    topicToRegister = CRN
    print(topicToRegister)
    
    for courseArn in allTopics['Topics']: # Iterate through all 
    	if topicToRegister in courseArn['TopicArn']: # Set flag to True, if topic is present
    		TopicPresent = True
    		TopicArntosend = courseArn['TopicArn']
    
	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Topic.subscribe
    if TopicPresent:
         # Send out subsctiption email to confirm
        response = client.publish(
            TopicArn=TopicArntosend, 
            Subject=''+subjectNames[CRN]+" has seats available",
            Message=''+subjectNames[CRN]+" has seats available , CRN is :"+CRN+". Register at https://register.dal.ca/StudentRegistrationSsb_PROD/ssb/term/termSelection?mode=registration"
        )
        print(response)
    else:
        print("Topic not present")
    print("Email sent")
    



