import pprint
import shlex
import urllib.parse
import json
import subprocess
import urllib.request as urlrq
import ssl
import os
import sys
import logging
from datetime import *
import boto3
import requests
import base64
from botocore.exceptions import ClientError

logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context

file_name,secret_name, region, volume_name,rid = sys.argv

def get_secret(secret_name, region_name):

    secret = ''
    session = boto3.session.Session(profile_name="nasuni")
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
   
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print(
                "The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']

        else:
            secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])

    secret=json.loads(secret)
    return secret


secret = get_secret(secret_name, region)
endpoint=secret['nmc_api_endpoint']
username=secret['nmc_api_username']
password=secret['nmc_api_password']
web_access_appliance_address=secret['web_access_appliance_address']

try:

    session = boto3.Session(profile_name="nasuni")
    credentials = session.get_credentials()

    credentials = credentials.get_frozen_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    access_key_file = open('Zaccess_' + rid + '.txt', 'w')
    access_key_file.write(access_key)

    secret_key_file = open('Zsecret_' + rid + '.txt', 'w')
    secret_key_file.write(secret_key)
    access_key_file.close()
    secret_key_file.close()

except Exception as e:
    print('Runtime error while extracting aws keys')

try:
    logging.info(sys.argv)
    url = 'https://' + endpoint + '/api/v1.1/auth/login/'
    logging.info(url)
    values = {'username': username, 'password': password}
    data = urllib.parse.urlencode(values).encode("utf-8")
    logging.info(data)
    response = urllib.request.urlopen(url, data, timeout=5)
    logging.info(response)
    result = json.loads(response.read().decode('utf-8'))
    logging.info(result)

    cmd = 'curl -k -X GET -H \"Accept: application/json\" -H \"Authorization: Token ' + result[
        'token'] + '\" \"https://' + endpoint + '/api/v1.1/volumes/\"'
    logging.info(cmd)
    args = shlex.split(cmd)
    process = subprocess.Popen(
        args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    json_data = json.loads(stdout.decode('utf-8'))
    vv_guid = ''
    for i in json_data['items']:
        if i['name'] == volume_name:
            print(i)
            toc_file = open('nmc_api_data_root_handle_' + rid + '.txt', 'w')
            toc_file.write(i['root_handle'])
            # print('toc_handle',i['root_handle'])
            src_bucket = open(
                'nmc_api_data_source_bucket_' + rid + '.txt', 'w')
            src_bucket.write(i['bucket'])
            # print('source_bucket', i['bucket'])
            v_guid = open('nmc_api_data_v_guid_' + rid + '.txt', 'w')
            v_guid.write(i['guid'])
            vv_guid = i['guid']
            share_url = open(
                'nmc_api_data_external_share_url_' + rid + '.txt', 'w')
            share_url.write(web_access_appliance_address)

except Exception as e:
    print('Runtime Errors', e)
