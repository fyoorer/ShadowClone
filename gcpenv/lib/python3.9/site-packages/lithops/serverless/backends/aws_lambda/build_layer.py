import json
import subprocess
import os
import zipfile
import boto3
import sys
import shutil


TEMP_PATH = '/tmp'
LAYER_DIR_PATH = os.path.join(TEMP_PATH, 'modules', 'python')
LAYER_ZIP_PATH = '/tmp/layer.zip'


def add_directory_to_zip(zip_file, full_dir_path, sub_dir=''):
    for file in os.listdir(full_dir_path):
        full_path = os.path.join(full_dir_path, file)
        if os.path.isfile(full_path):
            zip_file.write(full_path, os.path.join(sub_dir, file), zipfile.ZIP_DEFLATED)
        elif os.path.isdir(full_path) and '__pycache__' not in full_path:
            add_directory_to_zip(zip_file, full_path, os.path.join(sub_dir, file))


def lambda_handler(event, context):
    if os.path.exists(LAYER_DIR_PATH):
        if os.path.isdir(LAYER_DIR_PATH):
            shutil.rmtree(LAYER_DIR_PATH)
        elif os.path.isfile(LAYER_DIR_PATH):
            os.remove(LAYER_DIR_PATH)

    os.makedirs(LAYER_DIR_PATH)

    command = [sys.executable, '-m', 'pip', 'install', '-t', LAYER_DIR_PATH]
    command.extend(event['dependencies'])
    subprocess.check_call(command)

    with zipfile.ZipFile(LAYER_ZIP_PATH, 'w') as layer_zip:
        add_directory_to_zip(layer_zip, os.path.join(TEMP_PATH, 'modules'))

    client = boto3.client('s3')
    with open(LAYER_ZIP_PATH, 'rb') as layer_zip:
        client.put_object(Body=layer_zip, Bucket=event['bucket'], Key=event['key'])

    return {
        'statusCode': 200,
        'body': json.dumps(event)
    }
