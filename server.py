import hashlib
import hmac
import base64
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
from typing import Optional

app = FastAPI()
SECRET_KEY = 'ee45adfb6afdea70c0f2c42409b319c6083065a0b5e88883be7bf90f6e8d6c53'
PASSWORD_SALT = '85137f242b5fbdaaf7655201660d4a048986b8bd5f832a00c607133ae2c63e67'


def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256(
        (password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash


users = {
    'alexey@user.com': {
        'name': 'Alexey',
        'password': 'bfefb234c87b0652102bf0dec66999fc0c8c39a7009ab1a363941372853e5fa3',
        'balance': 100_000
    },
    'petr@user.com': {
        'name': 'Petr',
        'password': '0cb932175764d52d20675edad742125bd94c03930c305c63ecd1a565037fc4f8',
        'balance': 555_555
    }
}


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return Response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Hello {users[valid_username]}', media_type='text/html')


@app.post('/login')
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response('I don\'t now you', media_type='text/html')
    response = Response(
        f'Login {username}, password_hash: {users[username]["password"]}',
        media_type='text/html')
    username_signed = base64.b64encode(username.encode()).decode() + '.' + \
                      sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
