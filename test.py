from utils import *
from config import pp

conatner_p = '/media/webguy/ubstrg/permitted_storage/VSCODE_GIT/OWN/PDF_tool/'+'/files/contracts'
file_n = 'ticketsSHOHOZ.COM_TICKET202202241240161208340_KF0Y_20221031.pdf'

rrr = read_and_process_pdf(conatner_p+'/'+'PullData.pdf', {'pull':{'start_left':4, 'end_right':5, 'count':0, 'appearance':[]}})
pp.pprint(rrr[0])