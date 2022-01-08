import time
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
#configuro la conexion al servidor de mysql
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:Passw0rd@localhost/tp_apirest"

db = SQLAlchemy(app)
#definimos los modelos a usar, uno para un usuario para probar el login, y el resto con informacion de la oauth2


class Courses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), unique=True)
    created_at = db.Column(db.DateTime,default=db.func.now())
    start_at = db.Column(db.Date,nullable=False)
    hours = db.Column(db.Integer,nullable=False)
    finish_at = db.Column(db.Date,nullable=False)
    active = db.Column(db.Integer, nullable=False, default=1)

    def __str__(self):
        return self.name
    
    def get_end_date(self):
        return self.finish_at

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password_hashed = db.Column(db.String(128))

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id
    
    def set_password(self, password):
        self.password_hashed = generate_password_hash(password)

    #modificar el metodo de psssword.
    def check_password(self, password):
        return check_password_hash(self.password_hashed,password)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()