from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource, fields
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:p%40stgress@localhost:5433/flask_assignment'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my_secret_key'
db = SQLAlchemy(app)

api = Api(app, version='1.0', title='User API',
            description='A simple User API',
            doc='/swagger-ui')

api.authorizations = {
    'BearerAuth': {
        'type': 'apiKey',
        'name': 'Authorization',
        'in': 'header',
        'description': 'Enter your bearer token in the format **Bearer &lt;token>**'
    }
}


class RoleEnum(Enum):
    USER = 'user'
    ADMIN = 'admin'


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.now())
    update_date = db.Column(db.DateTime, onupdate=datetime.now())
    active = db.Column(db.Boolean, default=True)

    def __init__(self, username, first_name, last_name, email, password, role=RoleEnum.USER):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role


def create_default_admin():
    with app.app_context():
        if not User.query.first():
            admin_user = User(
                username='admin',
                first_name='Admin',
                last_name='Admin',
                email='admin@admin.com',
                password='admin',
                role=RoleEnum.ADMIN
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created.")


login_model = api.model('Login', {
    'username': fields.String(required=True, description='The username'),
    'password': fields.String(required=True, description='The password')
})

login_response_model = api.model('LoginResponse', {
    'message': fields.String(description='Response message'),
    'token': fields.String(description='JWT token')
})

register_model = api.model('Register', {
    'username': fields.String(required=True, description='The username'),
    'first_name': fields.String(required=True, description='The first name'),
    'last_name': fields.String(required=True, description='The last name'),
    'email': fields.String(required=True, description='The email'),
    'password': fields.String(required=True, description='The password')
})

register_response_model = api.model('RegisterResponse', {
    'message': fields.String(description='Response message')
})

change_password_model = api.model('ChangePassword', {
    'current_password': fields.String(required=True, description='The current password'),
    'new_password': fields.String(required=True, description='The new password')
})

change_password_response_model = api.model('ChangePasswordResponse', {
    'message': fields.String(description='Response message')
})

edit_user_model = api.model('EditUser', {
    'username': fields.String(description='The username'),
    'first_name': fields.String(description='The first name'),
    'last_name': fields.String(description='The last name'),
    'email': fields.String(description='The email'),
    'role': fields.String(description='The role'),
    'active': fields.Boolean(description='The active status')
})


edit_user_response_model = api.model('EditUserResponse', {
    'message': fields.String(description='Response message')
})


@api.route('/register')
class Register(Resource):
    @api.doc('register_user')
    @api.expect(register_model)
    @api.response(201, 'User registered successfully.', model=register_response_model)
    @api.response(400, 'Bad Request')
    def post(self):
        data = request.json
        username = data.get('username')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if User.query.filter_by(username=username).first():
            return {'message': 'Username already exists.'}, 400
        if User.query.filter_by(email=email).first():
            return {'message': 'Email already exists.'}, 400

        new_user = User(username=username, first_name=first_name, last_name=last_name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully.'}, 201


@api.route('/login')
class Login(Resource):
    @api.doc('login_user')
    @api.expect(login_model)
    @api.response(200, 'Login successful!', model=login_response_model)
    @api.response(401, 'Invalid username or password.')
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.now() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return {'message': 'Login successful!', 'token': token}, 200
        else:
            return {'message': 'Invalid username or password.'}, 401
        

@api.route('/change-password')
class ChangePassword(Resource):
    @api.doc('change_password', security='BearerAuth')
    @api.expect(change_password_model)
    @api.response(200, 'Password change successful.', model=change_password_response_model)
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    def post(self):
        token = request.headers.get('Authorization')

        if not token:
            return {'message': 'Token is missing!'}, 401

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return {'message': 'Token has expired!'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Token is invalid!'}, 401

        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        user = User.query.filter_by(id=user_id).first()

        if not user:
            return {'message': 'User does not exist.'}, 400

        if not check_password_hash(user.password, current_password):
            return {'message': 'Current password is incorrect.'}, 400

        user.password = generate_password_hash(new_password)
        db.session.commit()

        return {'message': 'Password change successful.'}, 200


@api.route('/edit-user')
@api.route('/edit-user/<string:username>')
class EditUser(Resource):
    @api.doc('edit_user', security='BearerAuth')
    @api.expect(edit_user_model)
    @api.response(200, 'User details updated successfully.')
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    @api.response(403, 'Permission denied.')
    def put(self, username=None):
        token = request.headers.get('Authorization')

        if not token:
            return {'message': 'Token is missing!'}, 401

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_user = User.query.get(current_user_id)
        except jwt.ExpiredSignatureError:
            return {'message': 'Token has expired!'}, 401
        except jwt.InvalidTokenError:
            return {'message': 'Token is invalid!'}, 401

        if username:
            if current_user.role != RoleEnum.ADMIN:
                return {'message': 'Permission denied.'}, 403

            user_to_edit = User.query.filter_by(username=username).first()
            if not user_to_edit:
                return {'message': 'User not found.'}, 400
            if user_to_edit.role == RoleEnum.ADMIN and user_to_edit != current_user:
                return {'message': 'Cannot change status of another admin.'}, 403
        else:
            user_to_edit = current_user

        data = request.json
        if 'username' in data and data['username'] != user_to_edit.username:
            if User.query.filter_by(username=data['username']).first():
                return {'message': 'Username already exists.'}, 400
            user_to_edit.username = data['username']
        if 'first_name' in data:
            user_to_edit.first_name = data['first_name']
        if 'last_name' in data:
            user_to_edit.last_name = data['last_name']
        if 'email' in data:
            user_to_edit.email = data['email']
        if 'role' in data:
            if current_user.role == RoleEnum.ADMIN:
                if user_to_edit != current_user and user_to_edit.role == RoleEnum.ADMIN:
                    return {'message': 'Cannot change role of another admin.'}, 403
                if data['role'] == 'admin' and user_to_edit.role == RoleEnum.USER:
                    user_to_edit.role = RoleEnum.ADMIN
                elif data['role'] == 'user' and user_to_edit.role == RoleEnum.ADMIN:
                    user_to_edit.role = RoleEnum.USER
            else:
                return {'message': 'You cannot change your own role.'}, 403

        if 'active' in data:
            if current_user.role == RoleEnum.ADMIN:
                if user_to_edit != current_user and user_to_edit.role == RoleEnum.ADMIN:
                    return {'message': 'Cannot change active status of another admin.'}, 403
                user_to_edit.active = data['active']
            else:
                return {'message': 'You cannot change active status.'}, 403

        db.session.commit()

        return {'message': 'User details updated successfully.'}, 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)
