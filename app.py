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

# Add security definitions
api.security = [{'BearerAuth': []}]

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)
