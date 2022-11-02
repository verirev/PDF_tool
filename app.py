import os
import json
import base64
from flask import Flask, flash, render_template, request, redirect, url_for, send_from_directory, session, make_response, jsonify, Markup, g, abort
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
import requests
from config import *

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=f'{BASE_URL}/callback'
)

from werkzeug.utils import secure_filename
# from werkzeug.contrib.fixers import ProxyFix
from werkzeug.exceptions import BadRequest, InternalServerError, Forbidden, HTTPException, NotFound

# This one is for ubuntu server
# from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config['SECRET_KEY'] = '8870821eedywuiedywi' #Randomly generated
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

def file_access_util(file_id, user_id):
    from utils import file_access_checker
    value_got = file_access_checker(file_id, user_id)
    if value_got == 'access_granted':
        return True
    elif value_got == 'access_denied':
        raise Forbidden
    elif value_got == 'not_found':
        raise NotFound

@app.route('/', methods=['GET'])
@is_logged_in
def dashboard():
    user_id = session.get('user_id', 'NoIDinSession')
    from utils import get_list_of_file_d
    file_list = get_list_of_file_d({'user_id':user_id})
    return render_template('pages/dashboard.html', file_list = file_list)

@app.route('/file/view/<file_id>', methods=['GET'])
def file_view(file_id):
    user_id = session.get('user_id', 'NoIDinSession')
    file_access_util(file_id, user_id)
    return render_template('file_view.html')

@app.route('/file/single/<filename>', methods=['GET'])
@is_logged_in
def file_single(filename):
    return send_from_directory(app.config['UPLOADED_PDFILES_DEST'], filename)

@app.route('/file/upload', methods=['GET', 'POST'])
@is_logged_in
def file_upload():
    user_id = session.get('user_id', 'NoIDinSession')
    from utils import create_trx, file_info_saver
    pdform = PDFUploadForm()
    if pdform.validate_on_submit():
        filename_original = pdform.pdf_file.data.filename
        fname1 = filename_original.split('.pdf')[0].replace(' ','_')
        name_to_save = f'{fname1}_{create_trx(4)}_{datetime.now().strftime("%Y%m%d")}.pdf'
        filename_saved = pdfiles.save(storage = pdform.pdf_file.data, name = name_to_save)
        file_url = url_for('file_single', filename = filename_saved)
        file_id = file_info_saver(name_to_save, file_url, user_id)
    else:
        file_url = None
        file_id = None
    return render_template('pages/upload_page.html', form = pdform, file_url = file_url, file_id = file_id)

@app.route('/file/delete/<file_id>', methods=['POST'])
@is_logged_in
def file_delete(file_id):
    user_id = session.get('user_id', 'NoIDinSession')
    file_access_util(file_id, user_id)
    return jsonify({'status':True})

@app.route('/file/add/keywords/<file_id>', methods=['GET', 'POST'])
@is_logged_in
def file_uadd_keywords(file_id):
    from utils import get_file_by_id, update_kw
    user_id = session.get('user_id', 'NoIDinSession')
    file_access_util(file_id, user_id)
    if request.method == 'POST':
        # Add keywords part
        kw_d = request.json.get('kw', {})
        status = update_kw(file_id, kw_d)
        return jsonify({'status':status})
    file_dict = get_file_by_id(file_id, user_id)
    keyword_dict = file_dict.get('keyword_dict', {})
    return render_template('pages/add_keywords.html', file_dict = file_dict, keyword_dict = keyword_dict )

@app.route('/report/<file_id>', methods=['GET', 'POST'])
@is_logged_in
def report_getter(file_id):
    user_id = session.get('user_id', 'NoIDinSession')
    file_access_util(file_id, user_id)
    from utils import get_file_by_id, report_gen, report_processor
    file_dict = get_file_by_id(file_id, user_id)
    file_report_d = file_dict.get('report', {})
    file_report_list = file_report_d.get('report_list', {})
    generated_at = file_report_d.get('report_time', 'Undefined')
    report_bool = bool(file_report_list)
    if request.method == 'POST':
        # Generate report
        generate_b = request.json.get('generate', True)
        status = report_gen(file_id, app.config['UPLOADED_PDFILES_DEST'], user_id)
        return jsonify({'status':status})
    report_processed = report_processor(report_bool, file_report_list)
    return render_template('pages/report_getter.html', file_dict = file_dict, report_bool = report_bool, file_report_list = file_report_list, generated_at = generated_at, report_processed = report_processed, key_list_title = ['Keyword', 'Start left', 'End right', 'Appearance Count'])

@app.route('/download/report/<file_id>', methods=['GET'])
def report_downloads(file_id):
    from utils import excel_output
    excel_output_book = excel_output(file_id)
    file_name_str = 'Report_{}'.format(file_id)
    return excel.make_response_from_book_dict(excel_output_book, 'xlsx',file_name = file_name_str)

@app.route('/register',methods=['GET','POST'])
def register():
    from utils import register_new, create_trx
    from passlib.hash import pbkdf2_sha512
    login_error_message = 'Registration status: '
    session.clear()
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password_plain = request.form['password']
        user_id = create_trx(8)
        status_d = register_new(email=email, name=name, password=password_plain, role='user', user_id= user_id)
        if not status_d.get('status', False):
            error = f"{login_error_message}{status_d.get('status', False)}\nReason: {status_d.get('msg', False)}"
            return render_template('register/register.html', error=error)
        else:
            session['username'] = email
            session['logged_in'] = True
            session['role'] = 'user'
            session['user_id'] = user_id
            session['registered_from'] = 'email_module'
            return redirect(url_for('dashboard'))
    return render_template('register/register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    from utils import password_getter, user_getter
    from passlib.hash import pbkdf2_sha512
    login_error_message = 'Wrong Username or Password'
    session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']
        #get hashed password from mongo
        password_obj = password_getter(username)
        user_got = user_getter({'username':username})
        if password_obj['status'] == True:
            if pbkdf2_sha512.verify(password_candidate, password_obj['password']):
                session['username'] = username
                session['logged_in'] = True
                session['role'] = 'user'
                session['user_id'] = user_got.get('user_id', '')
                session['registered_from'] = 'email_module'
                return redirect(url_for('dashboard'))
            else:
                error = login_error_message
                return render_template('login/login.html', error=error)
        else:
            error = login_error_message
            return render_template('login/login.html', error=error)
    return render_template('login/login.html')

@app.route('/login/authorization/google')
def login_auth_google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    from utils import register_new_google, user_getter, create_trx
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    getter_d = {'google_id': id_info.get("sub"), 'name':id_info.get("name")}
    user_got = user_getter(getter_d)
    if bool(user_got):
        session['username'] = id_info.get("sub")
        session['logged_in'] = True
        session['role'] = 'user'
        session['user_id'] = user_got.get('user_id', '')
        session['registered_from'] = 'google'
    else:
        _saver_d = {'username':id_info.get("sub"), 'role':'user', 'user_id':create_trx(8)}
        saver_d = {**_saver_d, **getter_d}
        user_added = register_new_google(saver_d)
        app.logger.debug(f'user_added:{user_added}')
        session['username'] = id_info.get("sub")
        session['logged_in'] = True
        session['role'] = 'user'
        session['user_id'] = saver_d.get('user_id', '')
        session['registered_from'] = 'google'
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, threaded= True, port=5500)
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
