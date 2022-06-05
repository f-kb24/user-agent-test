import os
from dotenv import load_dotenv

load_dotenv(".env")

SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
SQLALCHEMY_TRACK_MODIFICATIONS = False
PROPAGATE_EXCEPTIONS = True
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET_KEY = os.getenv("SECRET_KEY")
CORS_EXPOSE_HEADERS = ["tokens", "Set-Cookie"]
CORS_SUPPORTS_CREDENTIALS = True
FLASK_RUN_PORT = 5555


# DEV
# SQLALCHEMY_ECHO = True
DEBUG = True
SQLALCHEMY_TRACK_MODIFICATIONS = False
PROPAGATE_EXCEPTIONS = True