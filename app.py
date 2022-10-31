import os
import json
import base64
from flask import Flask, flash, render_template, request, redirect, url_for, send_from_directory, session, make_response, jsonify, Markup, g
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired, FileSize
from wtforms import SubmitField
import flask_excel as excel
from passlib.hash import pbkdf2_sha512
from flask_uploads import UploadSet, configure_uploads
from functools import wraps
from threading import Thread
import logging
from config import *

from werkzeug.utils import secure_filename
# from werkzeug.contrib.fixers import ProxyFix
from werkzeug.exceptions import BadRequest, InternalServerError, Forbidden, HTTPException, NotFound

# This one is for ubuntu server
# from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config['SECRET_KEY'] = '8870821e-e123-4277-b918-66222afe4a29-fb8bba96-c1ab-47d0-8baf-a8f1aabe0b31' #Randomly generated
app.config['UPLOAD_FOLDER'] = PROJECT_ROOT+'/files'
app.config['UPLOADED_PDFILES_DEST']=PROJECT_ROOT+'/files/contracts'
app.config['UPLOADED_PDFILES_ALLOW'] = set(['pdf'])
pdfiles = UploadSet(name='pdfiles', extensions=('pdf'))

configure_uploads(app, (pdfiles))

csrf = CSRFProtect(app)
excel.init_excel(app)

@app.before_request
def session_checker():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)
    session.modified = True


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        username = session.get('username','')
        username_bool = bool(username)
        logged_in_bool = 'logged_in' in session
        if logged_in_bool and username_bool:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap


def is_logged_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        username = session.get('username','')
        role = session.get('role','')
        logged_in_bool = 'logged_in' in session
        if logged_in_bool and bool(username) and role == 'admin':
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap



@app.errorhandler(InternalServerError)
def e_500(e):
    app.logger.debug(e)
    return render_template('errors/generic_error.html'), 500

@app.errorhandler(HTTPException)
def e_http(e):
    app.logger.debug(e)
    return render_template('errors/generic_error.html'), 500

@app.errorhandler(Forbidden)
def e_forbidden(e):
    app.logger.critical(e)
    return render_template('errors/forbidden_error.html'), 401

@app.errorhandler(BadRequest)
def e_bad(e):
    app.logger.error(e)
    return redirect(url_for('logout'))

@app.errorhandler(NotFound)
def e_404(e):
    app.logger.debug(e)
    return render_template('errors/404_error.html'), 404

class PDFUploadForm(FlaskForm):
    pdf_file = FileField(
        validators = [
            FileAllowed(pdfiles, 'Only pdf files are allowed'),
            FileRequired('Must upload a file')
        ]
    )
    submit = SubmitField('Upload') 

@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/file/view', methods=['GET'])
def file_view():
    file_id = request.args.get('file_id', None)
    return render_template('file_view.html')

@app.route('/file/upload', methods=['GET', 'POST'])
def file_upload():
    from utils import create_trx
    pdform = PDFUploadForm()
    if pdform.validate_on_submit():
        filename_original = pdform.pdf_file.data.filename
        fname1 = filename_original.split('.pdf')[0].replace(' ','_')
        name_to_save = f'{fname1}_{create_trx(4)}_{datetime.now().strftime("%Y%m%d")}.pdf'
        filename_saved = pdfiles.save(storage = pdform.pdf_file.data, name = name_to_save)
    return render_template('upload_page.html')

@app.route('/file/delete/<file_id>', methods=['POST'])
def file_delete(file_id):
    return jsonify({'status':True})

@app.route('/file/add/keywords/<file_id>', methods=['GET', 'POST'])
def file_uadd_keywords(file_id):
    if request.method == 'POST':
        # Add keywords part
        pass
    return render_template('add_keywords.html')

@app.route('/report/<file_id>', methods=['GET'])
def report_getter(file_id):
    # file_id = request.args.get('file_id', None)
    return render_template('report_getter.html')

@app.route('/download/report/<file_id>', methods=['GET'])
def report_downloads(file_id):
    from utils import excel_output
    excel_output_book = excel_output(file_id)
    file_name_str = 'Report_{}'.format(file_id)
    return excel.make_response_from_book_dict(excel_output_book, 'xlsx',file_name = file_name_str)



if __name__ == '__main__':
    app.run(debug=True, threaded= True, port=5500)
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
