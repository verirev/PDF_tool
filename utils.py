from datetime import datetime
import re
from PyPDF2 import PdfFileReader
from db_utils import setter_file_single, getter_file_single, updater_file_single

def create_trx(size:int,mode='s'):
    import random
    import string
    if mode == 'm':
        chars = string.ascii_letters + string.digits
    else:
        chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(size))

def password_getter(username):
    from config import database
    admin_log_c = database['users']
    counted_records=admin_log_c.count_documents({'username':username})
    if counted_records >0:
        record_got=admin_log_c.find_one({'username':username})
        password_hash = record_got['password']
        return {'status':True,'msg':'Success', 'password':password_hash}
    else:
        return {'status':False,'msg':'No user found'}

def register_new(email='', name='', password='admin@ADMIN', user_id =create_trx(8), role = 'admin'):
    from db_utils import getter_user_count, setter_user_single
    finder_d = {'email':email, 'registered_from':'email_module'}
    if not bool(getter_user_count(finder_d)):
        saver_d = {'email':email, 'username':email, 'name':name, 'role':role, 'registered_from':'email_module'}
        from passlib.hash import pbkdf2_sha512
        new_password = pbkdf2_sha512.hash(password)
        saver_d['password'] = new_password
        saver_d['user_id'] = create_trx(8)
        save_status = setter_user_single(saver_d)
        return {'status': save_status, 'msg':''}
    else:
        return {'status':False, 'msg':'User Exists'}

def register_new_google(saver_d = {}):
    from config import database
    file_log_c = database['users']
    from passlib.hash import pbkdf2_sha512
    saver_d['registered_from'] = 'google'
    saver_d['created_at'] = datetime.now()
    saver_d['updated_at'] = datetime.now()
    cursor_obj = file_log_c.insert_one(saver_d)
    return bool(cursor_obj.inserted_id)

def user_getter(getter_d = {}):
    from db_utils import getter_user_single
    return getter_user_single(getter_d)

def read_and_process_pdf(full_file_path:str, dict_of_kw:dict)->dict:
    """Input like 
    dict_of_kw = {
        'keyword': {'start_left':int, 'end_right':int, 'count':int (default 0), 'appearance':[]},
        ....
    }

    Output like 
        list_of_kw = [
        {'keyword':'string', 'start_left':int, 'end_right':int, 'count':int, 'appearance':[
            {'page_no':int, 'extract_left':string, 'extract_right':string, 'started_at':int}
        ]},
        .....
    ]
    """
    with open(full_file_path, 'rb') as f:
        pdf = PdfFileReader(f)
        pdf_info = pdf.getDocumentInfo()
        number_of_pages = pdf.getNumPages()
        # print('number_of_pages', number_of_pages)
        for page_no in range(0, number_of_pages):
            single_page = pdf.getPage(page_no)
            text_in_page = single_page.extractText()
            # pdf_init_dict[page_no] = text_in_page
            for kw_string, dict_single in dict_of_kw.items():
                start_left = dict_single.get('start_left', 0)
                end_right = dict_single.get('end_right', 0)
                count_of_kw = dict_single.get('count', 0)
                count_in_current_page = text_in_page.count(kw_string)
                if bool(count_in_current_page):
                    count_of_kw += count_in_current_page
                    dict_single['count'] = count_of_kw
                    list_of_appearance = dict_single.get('appearance', [])
                    # Loop though count_in_current_page
                    list_of_indexes = [ i.start() for i in re.finditer(kw_string, text_in_page)]
                    print(list_of_indexes)
                    kw_len = len(kw_string)
                    text_len = len(text_in_page)
                    for idx in list_of_indexes:
                        appearance_dict = {'page_no':page_no+1}
                        appearance_dict['started_at'] = idx
                        # 'extract_left':string, 'extract_right':string
                        # get left extract 
                        if idx - start_left < 0:
                            start_at = idx - (idx - start_left)* -1
                            extract_left = text_in_page[start_at:idx]
                        elif idx - start_left >= 0:
                            extract_left = text_in_page[idx - start_left:idx]
                        else:
                            extract_left = ''
                        # get right extract 
                        end_idx = idx + kw_len
                        extract_right = text_in_page[end_idx:end_idx+end_right]
                        appearance_dict['extract_left'] = extract_left
                        appearance_dict['extract_right'] = extract_right
                        list_of_appearance.append(appearance_dict)
                    dict_single['appearance'] = list_of_appearance
        return dict_of_kw, pdf_info

def file_info_saver(file_name, file_url, user_id):
    file_id = create_trx(8)
    dict_to_save = { 'file_name': file_name, 'file_url': file_url, 'file_id': file_id, 'user_id':user_id }    
    setter_bool = setter_file_single(dict_to_save)
    if setter_bool:
        return file_id
    else:
        return None

def get_file_by_id(file_id, user_id):
    file_dict = getter_file_single({'file_id':file_id, 'user_id':user_id})
    return file_dict

def file_access_checker(file_id, user_id):
    from db_utils import getter_file_count
    count_by_file_id = getter_file_count({'file_id':file_id})
    count_by_user_and_file_id = getter_file_count({'file_id':file_id, 'user_id':user_id})
    if bool(count_by_user_and_file_id) == False and bool(count_by_file_id) == True:
        return 'access_denied'
    elif bool(count_by_user_and_file_id) == False and bool(count_by_file_id) == False:
        return 'not_found'
    else:
        return 'access_granted'

def file_info_updater(file_id, dict_to_update):
    finder_d  = {'file_id': file_id}
    setter_bool = updater_file_single(finder_d, dict_to_update)
    return setter_bool

def update_kw(file_id, kw_d):
    keyword_dict = {}
    for key_n, dict_single in kw_d.items():
        kw_string = dict_single.get('kw', 'NoKw')
        prefx = dict_single.get('prefx', 0)
        pstfx = dict_single.get('pstfx', 0)
        keyword_dict[kw_string] = {'start_left':prefx, 'end_right':pstfx, 'count':0, 'appearance':[]}
    return file_info_updater(file_id=file_id, dict_to_update={'keyword_dict':keyword_dict})

def get_list_of_file_d(finder_d = {}):
    from db_utils import getter_file_list
    return getter_file_list(finder_dict=finder_d ,sort_dict={'updated':-1})

def report_gen(file_id, container_dir, user_id):
    from config import pp
    file_dict = get_file_by_id(file_id, user_id)
    keyword_dict = file_dict.get('keyword_dict', {})
    file_name = file_dict.get('file_name', 'nofile')
    full_file_path = f'{container_dir}/{file_name}'
    dict_of_kw, pdf_info = read_and_process_pdf(full_file_path, keyword_dict)
    print(type(pdf_info))
    pp.pprint(pdf_info)
    #SAve to db
    dict_to_update = {'report':{'report_list':dict_of_kw, 'report_time':datetime.now()}}
    return file_info_updater(file_id=file_id, dict_to_update=dict_to_update)

def report_processor(report_bool, file_report_dict):
    key_list = []
    appearance_list = []
    if report_bool:
        for key, value in file_report_dict.items():
            key_items = [key, value.get('start_left', 0), value.get('end_right', 0), value.get('count', 0)]
            if key_items not in key_list:
                key_list.append(key_items)
            appearance_list.append(value.get('appearance', []))
    return [key_list, appearance_list]
            

def excel_output(file_id):
    return []




                        
                        









