from kinde_sdk.kinde_api_client import GrantType
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base configuration
SITE_HOST = os.environ.get("SITE_HOST", "localhost")
SITE_PORT = os.environ.get("SITE_PORT", "5000")
SITE_URL = f"http://{SITE_HOST}:{SITE_PORT}"
LOGOUT_REDIRECT_URL = f"{SITE_URL}/api/auth/logout"
KINDE_CALLBACK_URL = f"{SITE_URL}/api/auth/kinde_callback"

# Kinde configuration
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
KINDE_ISSUER_URL = os.environ.get("KINDE_ISSUER_URL", "https://nathalytoledo.kinde.com")

# Grant type configuration
GRANT_TYPE = GrantType.AUTHORIZATION_CODE_WITH_PKCE  # Keep as enum type
CODE_VERIFIER = os.environ.get("CODE_VERIFIER", "default_long_string_here")

# Flask session configuration
TEMPLATES_AUTO_RELOAD = True
SESSION_TYPE = "filesystem"
SESSION_PERMANENT = False
SECRET_KEY = os.environ.get("SECRET_KEY")

# Management API
MGMT_API_CLIENT_ID = os.environ.get("MGMT_API_CLIENT_ID")
MGMT_API_CLIENT_SECRET = os.environ.get("MGMT_API_CLIENT_SECRET")