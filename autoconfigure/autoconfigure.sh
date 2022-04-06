#!/bin/bash

python3 ReviewsToDynamoDb.py
python3 FallToDynamoDb.py
python3 WinterToDynamoDb.py
python3 SummerToDynamoDb.py
python3 CreateRdsTable.py
python3 testrds.py
