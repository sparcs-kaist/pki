DEBUG = True
SECRET_KEY = ''
SSO_CLIENT_ID = ''
SSO_CLIENT_KEY = ''


try:
    from pki.web.local_settings import *  # noqa: F401, F403
except ImportError:
    pass
