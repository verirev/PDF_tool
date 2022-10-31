from config import database, datetime, date, timedelta
from pymongo import ReturnDocument

def setter_file_single(dict_to_save = {}):
    collection_obj = database['fidict_to_savele_db']
    dict_to_save['created_at'] = datetime.now()
    dict_to_save['updated_at'] = datetime.now()
    cursor_obj = collection_obj.insert_one(dict_to_save)
    return bool(cursor_obj.inserted_id)

def updater_file_single(finder_dict = {}, dict_to_save = {}):
    collection_obj = database['file_db']
    dict_to_save['updated_at'] = datetime.now()
    cursor_obj = collection_obj.find_one_and_update(finder_dict, {'$set':dict_to_save}, return_document = ReturnDocument.AFTER)
    return bool(cursor_obj)

def getter_file_single(finder_dict = {}, projection_dict = {}):
    collection_obj = database['file_db']
    projection_dict['_id'] = False
    cursor_obj = collection_obj.find_one(finder_dict, projection = projection_dict)
    return cursor_obj

def getter_file_count(finder_dict = {}):
    collection_obj = database['file_db']
    cursor_obj = collection_obj.count_documents(finder_dict)
    return cursor_obj

def getter_file_list( finder_dict = {}, projection_dict = {}, sort_dict = {}):
    collection_obj = database['file_db']
    projection_dict['_id'] = False
    if bool(sort_dict):
        key_s = list(sort_dict.keys())[0]
        value_s = sort_dict[key_s]
        cursor_obj = collection_obj.find(finder_dict, projection = projection_dict).sort(key_s, value_s)
    else:
        cursor_obj = collection_obj.find(finder_dict, projection = projection_dict)
    return list(cursor_obj)