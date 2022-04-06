import json
import boto3

def lambda_handler(event, context):
    # TODO implement
    print(event)

    region_name = "us-east-1"

	# Creating a session
    session = boto3.Session(
        # aws_access_key_id="ASIAYGAALUVPDDNHDFN4",
        # aws_secret_access_key="MCDmvBf0QzH9FXzgWL7Btdx3coG8eLEz4YOGT2MW",
        # aws_session_token="FwoGZXIvYXdzEHwaDBZK03U3CPfkzhb6ryLAAWf160rQYXYL1hdUPVIvXN2vjBG/gczXL7igObF49xmv5gMfFYnPVLJW3si2eDvtMd9Vm4XURPtAa9WKMZYZFZk7IJlsXbfe3Zy6VjXjKGboQ8H0UMzJ4eZGH0Ye3w4PgB5kVSJLgRsMY33XmvgSjJ3ntrWtYppb9KzWH5CvKoPXvdVwfSzTSLJuLcEGfWTqJlQL6BNVPgvZ0iV1yynNO+O0aGKGcXE8FzcJagOSodUrqN8QjWWwACo2UJYbM/gfeSi10pKSBjIti53nm7Ik+uXzaOoUD6VtGm4aElfSdV6VtWvcTSnM3xYZL/cfgKAjU1A+o7uq",
        region_name = region_name)


	# Creating an sns session client
    client = session.client(
        service_name='sns',
        region_name=region_name
    )

	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.list_topics

    allTopics = client.list_topics()
    
    TopicPresent = False
    TopicArn = ""
    emailID = event['emailID']
    # emailID = emailID[0]
    topicToRegister = event['courseNum']
    
    print(event['emailID'])
    print(event['courseNum'])
    # topicToRegister = topicToRegister[0]

    for courseArn in allTopics['Topics']: # Iterate through all 
    	if topicToRegister in courseArn['TopicArn']: # Set flag to True, if topic is present
    		TopicPresent = True
    		TopicArn = courseArn['TopicArn']
    
	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Topic.subscribe
    if TopicPresent: # Send out subsctiption email to confirm
    	result = client.subscribe(TopicArn=TopicArn,Protocol='email',Endpoint=emailID)
    	print("Subcription email sent!") # Debugging purposes
    
    else: # Create a topic and then subscribe
    	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.create_topic
    	newTopic = client.create_topic(Name=topicToRegister)
    	print("Topic Created! ") # Debugging purposes
    	print(newTopic)
    	if newTopic['ResponseMetadata']['HTTPStatusCode'] == 200:
    	    result = client.subscribe(TopicArn=newTopic['TopicArn'],Protocol='email',Endpoint=emailID)
    	    print("Subcription email sent!") # Debugging purposes
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
