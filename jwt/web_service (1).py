from bottle import route ,run, request ,template ,static_file
import bottle
import datetime
import jwt
import json
import base64
def jwt_token_from_header():
    auth = bottle.request.headers.get('Authorization', None)
    if not auth:
        raise Exception({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'})
 
    parts = auth.split()
    print (parts )
    return parts[1]
    
def requires_auth(f):
    """Provides JWT based authentication for any decorated function assuming credentials available in an "Authorization" header"""
    def decorated(*args, **kwargs):
        try:
            token = jwt_token_from_header()
        except Exception as reason:
            bottle.abort(400, reason)
 
        try:
            # Headers = token[0]
            # payloads = token[1]
            # signature =token[2]
            # print (base64.decode(Headers) ,base64.decode(payloads))
            token_decoded = jwt.decode(token, "hellojwtworld" ,algorithm='HS256')    # throw away value
            print("heyyyy",token_decoded)
        except jwt.ExpiredSignature:
            bottle.abort(401, {'code': 'token_expired', 'description': 'token is expired'})
        except jwt.DecodeError as message:
            bottle.abort(401, {'code': 'token_invalid', 'description': message})
 
        return f(*args, **kwargs)
 
    return decorated
def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=900),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            "hellojwtworld",
            algorithm='HS256'
        ).decode('utf-8')
    except Exception as e:
        return e


@route("/helloworld","GET")
def first_function():
    return "helloworld my human"
    
@route("/login", "POST")
def  login_func():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if username== password:
        print( "<p>Your login information was correct.</p>" )
    else:
        print( "<p>Login failed.</p>" )
    token = encode_auth_token(username)
    print(token)
    return json.dumps({'token': token} )

@route("/jobs","GET")
@requires_auth
def get_protected_resource():
    print ("hello world")
    return {"status" :"succesfuulty accessed"}
@route('/')
def serve_homepage():
    return static_file("index.html", root='/home/mediaworker/jwt/')
run(host='192.168.1.58', port=5500)