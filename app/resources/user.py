from flask import request
from flask_restful import Resource
from models.user import UserModel
from argon2 import PasswordHasher


class CreateUser(Resource):
    @classmethod
    def post(cls):
        request_json = request.get_json()

        ph = PasswordHasher()
        hashed_password = ph.hash(request_json["password"])

        user = UserModel(username=request_json["username"], password=hashed_password)

        try:
            user.save_to_db()
        except Exception as e:
            print(e)
            return {"msg": "something went wrong when creating user"}, 500
        return {"msg": "user created"}, 201


class UserLogin(Resource):
    @classmethod
    def post(cls):
        request_json = request.get_json()
        user_agent = request.headers.get("User-Agent")
        ip_address = request.remote_addr

        auth_info = UserModel.login(
            request_json["username"], request_json["password"], user_agent, ip_address
        )
        if not auth_info["logged_in"]:
            return {"msg": "auth failed"}, 401
        if auth_info["warning"]:
            return {"msg": "auth succeeded", "warning": auth_info["warning"]}, 200
        return {"msg": "auth succeded"}, 200
