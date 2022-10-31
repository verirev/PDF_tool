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

import platform
platform_name=platform.system()

PROJECT_ROOT = os.getcwd()
PYTHON_MAJOR_MINOR = f'{sys.version_info.major}.{sys.version_info.minor}'

if platform_name == 'Linux' and platform.node() == 'webguy-beehive': # Development
    BASE_URL = 'http://127.0.0.1:5555'
elif platform_name == 'Darwin' and platform.node() == 'As-MacBook-Pro.local':# Development
    BASE_URL = 'http://127.0.0.1:5555'

db_client = pymongo.MongoClient("mongodb://localhost:27017/")
database = db_client['pdf_tool']


# print(platform_name, platform.node())