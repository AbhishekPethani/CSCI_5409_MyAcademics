import mysql.connector
import boto3
import json

def get_secret_value(name):
    secrets_client = boto3.client("secretsmanager",region_name='us-east-1')
    kwargs = {'SecretId': name}
    response = secrets_client.get_secret_value(**kwargs)
    return response

def getAllUsers():
    credentials = get_secret_value('project-video2')
    creds = json.loads(credentials['SecretString'])
    connection = mysql.connector.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='MyAcademics'
    )
    # check_table_existence()
    cursor = connection.cursor()
    cursor.execute("Select * from users")
    rows = cursor.fetchall()
    print(rows)

#  POST new students
def register():
    banner = "1234"
    email = "kp@gmail.com"
    firstname = "kandarp"
    lastname = "Parikh"
    password = "password123"
    credentials = get_secret_value('project-video2')
    creds = json.loads(credentials['SecretString'])
    connection = mysql.connector.connect(
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

if __name__ == '__main__':
    register()
    getAllUsers()
    