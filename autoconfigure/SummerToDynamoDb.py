#https://www.youtube.com/watch?v=MOaXGYgqipQ <-- Reference Video

import csv
import boto3

session = boto3.Session(region_name='us-east-1')

dynamodb = session.resource('dynamodb')

def write(tablename,rows):
    table = dynamodb.Table(tablename)

    with table.batch_writer() as batch:
        for row in rows:
            batch.put_item(Item={
             'CRN': int(row['CRN']),
             'CourseName':row['CourseName'],
             'Credit': int(row['Credit']),
             'Description': row['Description'],
             'Instructor': row['Instructor'],
             'Seats': int(row['Seats']),
             'Days': row['Days'],
             'Timings': row['Timings'],
             'Prerequisite': row['Prerequisite']
        })
    return True

def read_csv(csvFile, list):
    rows = csv.DictReader(open(csvFile))

    for row in rows:
        list.append(row)

if __name__ == '__main__':
    tablename = 'Summer_Courses'
    filename = 'SummerCourses.csv'
    items = []

    read_csv(filename,items)

    status = write(tablename,items)

    if(status):
        print("Data uploaded")

