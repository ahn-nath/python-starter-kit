from kinde_sdk.kinde_api_client import GrantType


SITE_HOST = "localhost"
SITE_PORT = "5000"
SITE_URL = f"http://{SITE_HOST}:{SITE_PORT}"
LOGOUT_REDIRECT_URL = f"http://{SITE_HOST}:{SITE_PORT}/api/auth/logout"
KINDE_CALLBACK_URL = f"http://{SITE_HOST}:{SITE_PORT}/api/auth/kinde_callback"
CLIENT_ID = "c41376bd84c24244b3122dd41cd154ba"
CLIENT_SECRET = "alAykn64XE0O2GPqJm0RoryqPGdEWHvMqF4IesTvvZFwBELOVu6"
KINDE_ISSUER_URL = "https://nathalytoledo.kinde.com"
GRANT_TYPE = GrantType.AUTHORIZATION_CODE_WITH_PKCE
CODE_VERIFIER = "joasd923nsad09823noaguesr9u3qtewrnaio90eutgersgdsfg" # A suitably long string > 43 chars
TEMPLATES_AUTO_RELOAD = True
SESSION_TYPE = "filesystem"
SESSION_PERMANENT = False
SECRET_KEY = "joasd923nsad09823noaguesr9u3qtewrnaio90eutgersgdsfgs" # Secret used for session management
MGMT_API_CLIENT_ID="c41376bd84c24244b3122dd41cd154ba"
MGMT_API_CLIENT_SECRET="alAykn64XE0O2GPqJm0RoryqPGdEWHvMqF4IesTvvZFwBELOVu6"
