from flask import Flask, Response, g, request

from flask_restful import Api
from flask_migrate import Migrate
from flask_cors import CORS

from utils.db import db

from resources.user import CreateUser, UserLogin

app = Flask(__name__)

app.config.from_pyfile("config.py")


@app.before_request
def find_user_agent():
    pass


CORS(app)
api = Api(app)
migrate = Migrate(app, db)
db.init_app(app)


api.add_resource(CreateUser, "/createuser")
api.add_resource(UserLogin, "/login")
