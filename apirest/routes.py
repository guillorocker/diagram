from flask import Blueprint,request,session, url_for
from flask import render_template, redirect, jsonify, Response
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import Courses, db, User, OAuth2Client
from .oauth2 import authorization, require_oauth
import time
from werkzeug.security import generate_password_hash, check_password_hash
import json

bp = Blueprint('home',__name__)
print(__name__)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/', methods=('GET', 'POST'))
def home():
    created = False
    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        _password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:    
            if not check_password_hash(user.password_hashed,_password):
                return render_template('home.html',badpassword=True)
        if not user:            
            user_dict = User(username=username)
            user_dict.set_password(_password)

            db.session.add(user_dict)
            db.session.commit()
            created = True
            user = User.query.filter_by(username=username).first()
        # if user is not just to log in, but need to head back to the auth page, then go for it
        session['id'] = user.id
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return render_template('home.html', user=user,created=created)

    user = current_user()
    if user:        
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('home.html', user=user, clients=clients)


@bp.route('/logout')
def logout():
    if session:
        del session['id']
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect('/')

#authorization_code 
@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    print(user)
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('apirest.routes.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
            #print(grant)
        except OAuth2Error as error:
            return error.error
            
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth2/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth2/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')



@bp.route('/Course',methods=['GET'])
@require_oauth('cursos')
def get_courses():
    courses = Courses.query.filter_by(active=1).all()
    course_dict = {}
    course_list = []
    if courses:
        #print(courses.__dict__)
        for item in courses:
            course_dict['id'] = item.id
            course_dict['name'] = item.name
            course_dict['created_at'] = item.created_at
            course_dict['start_at'] = item.start_at
            course_dict['hours'] = item.hours
            course_dict['finish_at'] = item.finish_at

            course_list.append(course_dict.copy())
    return jsonify({'Courses': course_list}),201


@bp.route('/Course',methods=['POST'])
@require_oauth('cursos')
def create_courses():
    data = request.json
    course_dict = {}
    if data:
        try:
            curso = Courses(name= data['name'],start_at = data['start_at'],hours = data['hours'],finish_at = data['finish_at'])

            db.session.add(curso)
            db.session.commit()
            curso = Courses.query.filter_by(name=data['name']).first()
            course_dict['id'] = curso.id
            course_dict['name'] = curso.name
            course_dict['created_at'] = curso.created_at
            course_dict['start_at'] = curso.start_at
            course_dict['hours'] = curso.hours
            course_dict['finish_at'] = curso.finish_at
            return jsonify({'Course':course_dict}),201
        except Exception as err:
          return jsonify({'error':err}),401  
    return jsonify({'error':'Bad Request'}),401


@bp.route('/Course/<id>',methods=['PUT'])
@require_oauth('cursos')
def update_courses(id):
    data = request.json
    course_dict = {}
    curso = Courses.query.filter_by(id=id).first()
    if curso:
        name = data.get('name',curso.name) 
        start_at = data.get('start_at',curso.start_at) 
        hours = data.get('hours',curso.hours)
        finish_at = data.get('finish_at',curso.finish_at) 
        
        curso.name = name
        curso.start_at = start_at
        curso.hours = hours
        curso.finish_at = finish_at
        
        db.session.commit()
    
        course_dict['id'] = curso.id
        course_dict['name'] = curso.name
        course_dict['created_at'] = curso.created_at
        course_dict['start_at'] = curso.start_at
        course_dict['hours'] = curso.hours
        course_dict['finish_at'] = curso.finish_at
        return jsonify({'Course':course_dict}),201
    return jsonify({'Course':'course not Found'}),404

@bp.route('/Course/<id>',methods=['DELETE'])
@require_oauth('cursos')
def delete_courses(id):
    data = request.json
    course_dict = {}
    curso = Courses.query.filter_by(id=id).first()
    if curso:
        Courses.query.filter_by(id=id).delete()
       
        db.session.commit()
    
        return jsonify({'Course':'deleted'}),201