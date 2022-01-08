from apirest.app import create_app


app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    "SQLALCHEMY_DATABASE_URI":"mysql+mysqlconnector://root:Passw0rd@localhost/tp_apirest"
})

