#recursos para el desarrollo del autorization server, y para el protector de recursos
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
#metodos para trabajar sobre la db
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
#metodos relacionados al flujo oauth2
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
#modelos y db
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token


#clase que majena la autorizacion
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    #metodo para extraer los datos del code generado via req, y los almaceno en la tabla "oauth2_code"
    def save_authorization_code(self, code, request):
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    #metodo para consultar el codigo de autorizacion, sino esta expirado    
    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if auth_code and not auth_code.is_expired():
            return auth_code
    

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    
    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)
    
    #clase para manejar el flujo de grnat de password.
class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    
    #metodo para autenticar usuarios via user y password
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            return user

        #

class RefreshTokenGrant(grants.RefreshTokenGrant):
    
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()

#inicializo propiedades para el servidor de autorizacion.
query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token)
#inicializo el servidor de autorizacion
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
#inicializo el decorador para proteger los endpoint.
require_oauth = ResourceProtector()


def config_oauth(app):
    authorization.init_app(app)

    # soporta todos los grants
    authorization.register_grant(grants.ImplicitGrant)
    authorization.register_grant(grants.ClientCredentialsGrant)
    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())