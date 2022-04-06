#https://www.youtube.com/watch?v=MOaXGYgqipQ <-- Reference Video

import csv
import boto3

session = boto3.Session(region_name="us-east-1")

dynamodb = session.resource('dynamodb')

def write(tablename,rows):
    table = dynamodb.Table(tablename)

    with table.batch_writer() as batch:
        for row in rows:
            batch.put_item(Item={
             'CRN': (row['CRN']),
             'Reviews':row['Reviews'],
             'Stars': (row['Stars']),
        })
    return True

def read_csv(csvFile, list):
    rows = csv.DictReader(open(csvFile))

    for row in rows:
        list.append(row)

if __name__ == '__main__':
    tablename = 'Reviews'
    filename = 'Reviews.csv'
    items = []

    read_csv(filename,items)

    status = write(tablename,items)

    if(status):
        print("Data uploaded")

