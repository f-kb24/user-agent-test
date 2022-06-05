from utils.db import db
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from datetime import datetime, timedelta
import copy


class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    log_info = db.Column(db.JSON(), default={"logs": []})

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def login(cls, username: str, password: str, user_agent, ip_address):
        user = cls.query.filter_by(username=username).first()
        if not user:
            return {"logged_in": False, "user_id": None, "user": None}
        ph = PasswordHasher()

        try:
            ph.verify(user.password, password)
        except VerifyMismatchError:
            return {"logged_in": False, "user_id": None, "user": None}

        info = {
            "logged_in": True,
            "user_id": user.id,
            "warning": None,
            "user_agent": user_agent,
        }
        now = datetime.utcnow().isoformat()
        an_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()

        # check all the instances of logins within the past hour
        for log in user.log_info["logs"]:
            if log["date"] > an_hour_ago:
                if log["ip_address"] != ip_address:
                    info[
                        "warning"
                    ] = "separate IP address recorded within the past hour"

        info["date"] = now
        logss = copy.deepcopy(user.log_info)
        logss["logs"].append(info)

        user.log_info = logss
        user.save_to_db()

        info["user"] = user
        return info

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
