import json
import boto3 
import json
import pymysql
from botocore.exceptions import ClientError
from botocore.vendored import requests
try:
    from urllib.parse import urlparse, urlencode, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import urlencode
import re
import sys
from boto3 import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from boto3.dynamodb.conditions import Key
secret_name = "project-video2"
def lambda_handler(event, context):
    print(event)
    if(event['User']['Operation']=="verify"):
        result = verifyUser(event)
        # return {
        #     'statusCode': 200,
        #     'body': json.dumps(result)
        # }
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    if(event['User']['Operation']=="addreview"):
        result = addreview(event)
        # return {
        #     'statusCode': 200,
        #     'body': json.dumps(result)
        # }
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

    if(event['User']['Operation']=="getreview"):
        result = getReviews(event)
        # return {
        #     'statusCode': 200,
        #     'body': json.dumps(result)
        # }
        return {
            'statusCode': 200,
            'reviews': result[0]['Reviews'],
            'stars': result[0]['Stars']
        }
    
    if(event['User']['Operation'] == "register"):
        result = register(event)
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    if(event['User']['Operation'] == "getcrn"):
        result = getCRN(event)
        return {
            'statusCode': 200,
            'body': result
        }

    if(event['User']['Operation'] == "addcrn"):
        result = addCRN(event)
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

def addreview(event):
    tablename = "Reviews"
    session = boto3.Session()
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(tablename)
    currentReviews = getReviews(event)
    print(currentReviews)
    for review in event['User']['review']:
        if(len(currentReviews[0]['Reviews'])>0):
            response = table.update_item(
                Key={
                    'CRN': event['User']['CRN']
                },
                UpdateExpression="set Reviews=:review,Stars=:stars",
                ExpressionAttributeValues={
                    ':review': currentReviews[0]['Reviews']+","+event['User']['review'],
                    ':stars': str(currentReviews[0]['Stars'])+","+str(event['User']['stars'])
                },
                ReturnValues="UPDATED_NEW"
            )
        else:
            response = table.update_item(
                Key={
                    'CRN': event['User']['CRN']
                },
                UpdateExpression="set Reviews=:review,Stars=:stars",
                ExpressionAttributeValues={
                    ':review': event['User']['review'],
                    ':stars': event['User']['stars']
                },
                ReturnValues="UPDATED_NEW"
            )
    return True
    
def getReviews(event):
    tablename = "Reviews"
    session = boto3.Session()
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table(tablename)
    response = table.query(
        KeyConditionExpression=Key('CRN').eq(event['User']['CRN'])
    )
    print(response['Items'])
    return response['Items']
    
def signing_headers(method, url_string, body):
    # Adapted from:
    #   https://github.com/jmenga/requests-aws-sign/blob/master/requests_aws_sign/requests_aws_sign.py
    region = re.search("execute-api.(.*).amazonaws.com", url_string).group(1)
    url = urlparse(url_string)
    path = url.path or '/'
    querystring = ''
    if url.query:
        querystring = '?' + urlencode(
            parse_qs(url.query, keep_blank_values=True), doseq=True)

    safe_url = url.scheme + '://' + url.netloc.split(
        ':')[0] + path + querystring
    request = AWSRequest(method=method.upper(), url=safe_url, data=body)
    SigV4Auth(Session().get_credentials(), "execute-api",
              region).add_auth(request)
    print(dict(request.headers.items()))
    return dict(request.headers.items())

def addCRN(event):
    banner = event['User']['BannerId']
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    result = getCRN(event)
    if(len(result)>0):
        cursor = connection.cursor()
        statement = "UPDATE users SET CRN = '"+result+","+event['User']['CRN']+"' WHERE BannerID = '"+banner+"'"
        cursor.execute(statement)
        connection.commit()
    else:
        cursor = connection.cursor()
        statement = "UPDATE users SET CRN = '"+result+event['User']['CRN']+"' WHERE BannerID = '"+banner+"'"
        cursor.execute(statement)
        connection.commit()
    statement = "Select Email from users WHERE BannerId = '"+banner+"'"
    cursor = connection.cursor()
    cursor.execute(statement)
    rows = cursor.fetchall()
    emailId = ""
    if(len(rows)>0):
        for x in rows:
            if x[0] is not None:
                emailId = emailId + x[0]
    print(emailId)
    method = "post"
    url = "https://fqacmd4z31.execute-api.us-east-1.amazonaws.com/test/subscribe"
    body = {
        "emailID": emailId,
        "courseNum": event['User']['CRN']
        }
    r = requests.post(url,json=body, headers=signing_headers(method, url, body))
    print(r.content.decode("utf-8"))
    return True

def getCRN(event):
    banner = event['User']['BannerId']
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    statement = "Select CRN from users WHERE BannerId = '"+banner+"'"
    cursor = connection.cursor()
    cursor.execute(statement)
    rows = cursor.fetchall()
    crns = ""
    if(len(rows)>0):
        for x in rows:
            if x[0] is not None:
                crns = crns + x[0]
    return crns
    

def register(event):
    print(event['User']['BannerId'])
    banner = event['User']['BannerId']
    email = event['User']['Email']
    firstname = event['User']['FirstName']
    lastname = event['User']['LastName']
    password = event['User']['Password']
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    cursor = connection.cursor()
    statement = "INSERT INTO users (BannerId, Email, FirstName, LastName,Password) VALUES (%s, %s,%s, %s,%s)"
    val = (banner, email,firstname,lastname,password)
    cursor.execute(statement, val)
    connection.commit()
    return True
    
    

def delete():
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database=creds['dbname']
    )
    cursor = connection.cursor()
    cursor.execute("DROP TABLE users")
    cursor.close()

    return {'message' : 'success'}


# GET all students data
def getAllUsers():
    credentials = get_secret_value(secret_name)
    print(credentials)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    print(creds)
    # check_table_existence()
    cursor = connection.cursor()
    cursor.execute("Select * from users")
    rows = cursor.fetchall()
    return rows

def verifyUser(event):
    password = event['User']['Password']
    banner = event['User']['BannerId']
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    # check_table_existence()
    statement = "Select Password from users WHERE BannerId = '"+banner+"'"
    cursor = connection.cursor()
    cursor.execute(statement)
    rows = cursor.fetchall()
    print(rows)
    for x in rows:
        if(x[0] == password):
            return True
        else:
            return False
    return False



#  POST new students
def storedata():
    print('Store Students data called')
    if request.is_json:
        data = request.get_json()
        if(data["user"]):
            for x in range(0,len(data['user'])):
                if(len(data['user'][x]['banner'])==0):
                    return {'status':'400','error':'banner is primary key and cant be empty'}
            insert_to_database(data["user"])
            return {"status":'200'}
        else:
            return {"status": '400',"error":"Json does not have 'students' key"}
    else:
        return {'error' : 'invalid json'}


def insert_to_database(database_record): 
    credentials = get_secret_value(secret_name)
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database=creds['dbname']
    )
    cursor = connection.cursor()
    check_table_existence()
    for x in range(0,len(database_record)):
        first_name = (database_record[x]['first_name'])
        last_name = (database_record[x]['last_name'])
        banner = (database_record[x]['banner'])
        data = {'first_name': first_name, 'last_name': last_name, 'banner': banner}
        query = "insert into students (first_name, last_name, banner) values (%s, %s,%s)"
        value = (data['first_name'], data['last_name'],data['banner'])
        cursor.execute(query, value)
        connection.commit()

def get_secret_value(name):
    secrets_client = boto3.client("secretsmanager",region_name='us-east-1')
    kwargs = {'SecretId': name}
    response = secrets_client.get_secret_value(**kwargs)
    return response

def check_table_existence():
    credentials = get_secret_value('assignment3-secret-key')
    creds = json.loads(credentials['SecretString'])
    connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database=creds['dbname']
    )
    cursor = connection.cursor()
    query = "SHOW TABLES LIKE 'users'"
    cursor.execute(query)
    result = cursor.fetchone()
    if result:
        print("Table exists")
    else:
        cursor.execute(" CREATE TABLE users (BannerId int NOT NULL,Email varchar(45) DEFAULT NULL,FirstName varchar(45) DEFAULT NULL,LastName varchar(45) DEFAULT NULL,PhoneNumber varchar(45) DEFAULT NULL,Password varchar(45) DEFAULT NULL,PRIMARY KEY (BannerId))")
        print("Table created")