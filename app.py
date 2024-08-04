from flask import Flask, request
from flask_restx import Api, Resource, fields
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import jwt
import os
import binascii
from config import Config
from models import db, User, ResetToken, RoleEnum

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

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
            if current_user.id == user_to_edit.id:
                return {'message': 'You cannot edit your own role or active status.'}, 403
        else:
            user_to_edit = current_user

        data = request.json
        if 'username' in data:
            user_to_edit.username = data['username']
        if 'first_name' in data:
            user_to_edit.first_name = data['first_name']
        if 'last_name' in data:
            user_to_edit.last_name = data['last_name']
        if 'email' in data:
            user_to_edit.email = data['email']
        if 'role' in data and current_user.role == RoleEnum.ADMIN:
            user_to_edit.role = data['role']
        if 'active' in data and current_user.role == RoleEnum.ADMIN:
            user_to_edit.active = data['active']

        db.session.commit()

        return {'message': 'User details updated successfully.'}, 200

@api.route('/forgot-password')
class ForgotPassword(Resource):
    @api.doc('forgot_password')
    @api.expect(api.model('ForgotPassword', {'username': fields.String(required=True, description='The username')}))
    @api.response(200, 'Reset token generated.')
    @api.response(400, 'Bad Request')
    def post(self):
        data = request.json
        username = data.get('username')

        user = User.query.filter_by(username=username).first()
        if not user:
            return {'message': 'Username not found.'}, 400

        token = binascii.hexlify(os.urandom(24)).decode()
        reset_token = ResetToken(username=username, token=token)
        db.session.add(reset_token)
        db.session.commit()

        reset_url = f'http://localhost:5000/reset-password/{token}'

        return {'message': 'Reset token generated.', 'reset_url': reset_url}, 200

@api.route('/reset-password/<string:token>')
class ResetPassword(Resource):
    @api.doc('reset_password')
    @api.expect(api.model('ResetPassword', {
        'new_password': fields.String(required=True, description='The new password')
    }))
    @api.response(200, 'Password reset successful.')
    @api.response(400, 'Invalid token or token has been used.')
    def post(self, token):
        data = request.json
        new_password = data.get('new_password')

        reset_token = ResetToken.query.filter_by(token=token).first()

        if not reset_token or reset_token.is_used:
            return {'message': 'Invalid token or token has been used.'}, 400

        user = User.query.filter_by(username=reset_token.username).first()
        if not user:
            return {'message': 'User not found.'}, 400

        user.password = generate_password_hash(new_password)
        db.session.commit()

        reset_token.is_used = True
        db.session.commit()

        return {'message': 'Password reset successful.'}, 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)
