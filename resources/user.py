from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from passlib.hash import pbkdf2_sha256

from db import db
from models import UserModel
from schemas import UserSchema, UserLoginSchema, UserProtectedSchema


blp = Blueprint("Users", "users", description="Operations on users")

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(409, message="A user with that username already exists.")

        user = UserModel(
            username=user_data["username"],
            password=pbkdf2_sha256.hash(user_data["password"]),
            quote=user_data["quote"]
        )

        db.session.add(user)
        db.session.commit()

        return {"message": "User created successfully."}, 201

@blp.route("/login")
class UserRegister(MethodView):
    @blp.arguments(UserLoginSchema)
    def post(self, login_data):
        user = UserModel.query.filter(
            UserModel.username == login_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(login_data["password"], user.password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}, 200

        abort(401, message="Invalid credentials.")

@blp.route("/protected")
class UserRegister(MethodView):
    @jwt_required()
    @blp.response(200, UserProtectedSchema)
    def get(self):
        jwt = get_jwt()
        user_id = jwt.get("id")
        print(jwt)

        user = UserModel.query.filter(
            UserModel.id == user_id
        ).first()

        if user:
            return {
                "username": user.username,
                "quote": user.quote
                }, 200

        abort(401, message="Invalid credentials.")
