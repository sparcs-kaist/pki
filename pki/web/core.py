import hmac
import os
import time
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, make_response, redirect,
    render_template, request, send_file,
)
from OpenSSL import crypto as c

from pki.lib.core import (
    gen_crl, issue, LEAF_PATH, revoke, ROOT_CRL,
)
from pki.web.settings import (
    DEBUG, SECRET_KEY, SSO_CLIENT_ID, SSO_CLIENT_KEY,
)
from pki.web.sparcsssov2 import Client


BASE_PATH = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config.update({
    'DEBUG': DEBUG,
    'SECRET_KEY': SECRET_KEY,
})
client = Client(SSO_CLIENT_ID, SSO_CLIENT_KEY)


def generate_cookie(username, sid):
    expire = int(time.time()) + 600
    d = f'{username}:{sid}:{expire}'
    m = hmac.new(
        app.secret_key.encode(), d.encode(), 'sha256',
    ).hexdigest()
    return f'{d}:{m}'


def parse_cookie(cookie):
    l = cookie.strip().split(':')
    if len(l) != 4:
        return None, None, 0

    m = hmac.new(
        app.secret_key.encode(), ':'.join(l[:3]).encode(), 'sha256',
    ).hexdigest()
    if not secrets.compare_digest(m, str(l[3])):
        return None, None, 0
    return l[0], l[1], int(l[2])


def get_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cookie = request.cookies.get('sso', '')
        username, sid, expire = parse_cookie(cookie)
        if username and int(time.time()) < expire:
            kwargs['auth_info'] = {
                'username': username,
                'sid': sid,
                'expire': expire,
            }
        else:
            kwargs['auth_info'] = {'username': '', 'expire': 0}
        return f(*args, **kwargs)
    return decorated


def get_state(username):
    user_crt = os.path.join(LEAF_PATH, f'{username}.crt')
    if not os.path.exists(user_crt):
        return 'none', 0

    with open(user_crt, 'r') as f:
        cert = c.load_certificate(c.FILETYPE_PEM, f.read())

    serial = format(cert.get_serial_number(), 'x')
    with open(ROOT_CRL, 'r') as f:
        crl = ''.join(f.readlines())
        crl_obj = c.load_crl(c.FILETYPE_PEM, crl)
        revoked_list = crl_obj.get_revoked()
        revoked_list = [] if not revoked_list else revoked_list
        for rvk in revoked_list:
            rvk_serial = rvk.get_serial().decode()
            if rvk_serial == serial:
                return 'revoked', 0

    expire = datetime.strptime(
        cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ',
    )
    if expire < datetime.now():
        return 'expired', expire
    elif expire < datetime.now() - timedelta(days=10):
        return 'warn', expire
    return 'ok', expire


@app.route('/login/')
def login_init():
    login_url, state = client.get_login_params()
    return redirect(login_url)


@app.route('/login/callback/')
def login_callback():
    code = request.args.get('code', '')
    try:
        user_data = client.get_user_info(code)
    except:
        return redirect('/')

    cookie = generate_cookie(user_data['sparcs_id'], user_data['sid'])
    resp = make_response(redirect('/'))
    resp.set_cookie('sso', cookie, secure=(not app.debug))
    return resp


@app.route('/logout/')
@get_session
def logout(auth_info=None):
    if not auth_info['username']:
        return redirect('/')

    logout_url = client.get_logout_url(
        auth_info['sid'], f'https://{request.host}',
    )
    resp = redirect(logout_url)
    resp.set_cookie('sso', '', expires=0, secure=(not app.debug))
    return resp


@app.route('/')
@get_session
def main(auth_info=None):
    username = auth_info['username']
    s_expire = auth_info['expire'] - int(time.time())
    state, c_expire = get_state(username)
    return render_template(
        'main.html', username=username, state=state,
        s_expire=s_expire, c_expire=c_expire,
    )


@app.route('/action/')
@get_session
def action(auth_info=None):
    username = auth_info['username']
    if not username:
        return redirect('/')

    state, c_expire = get_state(username)
    user_p12 = os.path.join(LEAF_PATH, f'{username}.p12')

    try:
        if state in ['revoked', 'expired', 'none']:
            issue(username, 'user')
        elif state in ['warn', ]:
            revoke(username)
            gen_crl()
            issue(username, 'user')
    except Exception as e:
        return '<script>alert("Unknown error is occurred.");</script>'

    return send_file(
        user_p12, mimetype='application/x-pkcs12',
        as_attachment=True, attachment_filename=f'{username}.p12',
    )


@app.route('/sparcs.crl')
def crl():
    return send_file(ROOT_CRL)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=22223)
