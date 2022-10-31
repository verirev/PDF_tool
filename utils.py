import re
from PyPDF2 import PdfFileReader

def create_trx(size:int,mode='s'):
    import random
    import string
    if mode == 'm':
        chars = string.ascii_letters + string.digits
    else:
        chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(size))

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
        for page_no in range(1, number_of_pages+1):
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
                    kw_len = len(kw_string)
                    text_len = len(text_in_page)
                    for idx in list_of_indexes:
                        appearance_dict = {'page_no':page_no}
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
                        if end_idx > text_len-1:
                            extract_right = ''
                        else:
                            extract_right = text_in_page[end_idx:end_right]
                        appearance_dict['extract_left'] = extract_left
                        appearance_dict['extract_right'] = extract_right
                    list_of_appearance.append(appearance_dict)
                    dict_single['appearance'] = list_of_appearance
        return dict_of_kw, pdf_info

def excel_output(file_id):
    return []




                        
                        









