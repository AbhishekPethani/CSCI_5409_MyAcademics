
import boto3
import json
import mysql.connector

def get_secret_value(name):
    secrets_client = boto3.client("secretsmanager",region_name='us-east-1')
    kwargs = {'SecretId': name}
    response = secrets_client.get_secret_value(**kwargs)
    return response

def createTable():
    credentials = get_secret_value('project-video2')
    creds = json.loads(credentials['SecretString'])
    connection = mysql.connector.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database=creds['dbname']
    )
    cursor = connection.cursor()
    cursor.execute(" CREATE TABLE users (BannerId varchar(45) NOT NULL,Email varchar(45) DEFAULT NULL,FirstName varchar(45) DEFAULT NULL,LastName varchar(45) DEFAULT NULL,Password varchar(45) DEFAULT NULL,CRN varchar(45) DEFAULT NULL,PRIMARY KEY (BannerId))")
    print("Table created")

if __name__ == '__main__':
    createTable()
