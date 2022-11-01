import sys
import os
from datetime import datetime, timedelta, date
import pymongo
import bson
from pymongo import MongoClient , aggregation, collection, ReturnDocument
# import pytz
# from pytz import timezone
from dateutil.parser import parse
import pprint
pp = pprint.PrettyPrinter(indent=2)
import json

import platform
platform_name=platform.system()

PROJECT_ROOT = os.getcwd()
PYTHON_MAJOR_MINOR = f'{sys.version_info.major}.{sys.version_info.minor}'

if platform_name == 'Linux' and platform.node() == 'webguy-beehive': # Development
    BASE_URL = 'http://127.0.0.1:5500'
elif platform_name == 'Darwin' and platform.node() == 'As-MacBook-Pro.local':# Development
    BASE_URL = 'http://127.0.0.1:5500'

db_client = pymongo.MongoClient("mongodb://localhost:27017/")
database = db_client['pdf_tool']

# Google oauth stuffs
client_secrets_file = f'{os.getcwd()}/oauth/google/client_secret.json'
with open(client_secrets_file, 'r') as json_file:
    json_as_dict = json.loads(json_file.read())
    GOOGLE_CLIENT_ID = json_as_dict.get('web', {}).get('client_id', '')
    json_file.close()