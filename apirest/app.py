# website/app.py
from flask import Flask
from .routes import bp
from .models import db,app
from .oauth2 import config_oauth
import os


def create_app(config=None):
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'
    app = Flask(__name__)
    
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)    
    setup_app(app)
    return app

def setup_app(app):    
    @app.before_first_request
    def create_tables():
        db.create_all()
    db.init_app(app)
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')