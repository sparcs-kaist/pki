DEBUG = True
SECRET_KEY = ''
SSO_CLIENT_ID = ''
SSO_CLIENT_KEY = ''


try:
    from .local_settings import *  # noqa: F401, F403
except ImportError:
    pass
