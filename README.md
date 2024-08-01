# Flask REST API with PostgreSQL and SQLAlchemy
 All the APIs are created following OpenAPI Standards.
## Requirements

- Python
- PostgreSQL
- Flask
- Flask-RESTX
- Flask-SQLAlchemy
- PyJWT
- Werkzeug

## Setup Instructions

1. **Clone the repository:**
    ```bash
    git clone https://github.com/mashrufehsan/W3-Flask-Assignment.git
    cd W3-Flask-Assignment
    ```

2. **Create a virtual environment and activate it:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Setup PostgreSQL Database:**
    - Create a PostgreSQL database and user with the necessary privileges.
    - Update the database URI in `app.config['SQLALCHEMY_DATABASE_URI']` with your database credentials.

5. **Run the application:**
    ```bash
    python app.py
    ```

6. **Access Swagger-UI:**
    Open your web browser and go to `http://localhost:5000/swagger-ui`.

## Important!
Upon running the project first time, A table named ```users``` will be created along with a user by default with *****admin***** privilege.

        "username": "admin",
        "password": "admin"
This user is needed to perform further operations like promoting other users to admin.

## API Endpoints

### Register a User

- **Endpoint:** `/register`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "email": "johndoe@example.com",
        "password": "password123"
    }
    ```
- **Responses:**
    - `201`: User registered successfully.
    - `400`: Username or Email already exists.

### Login a User

- **Endpoint:** `/login`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "username": "johndoe",
        "password": "password123"
    }
    ```
- **Responses:**
    - `200`: Login successful, returns JWT token.
    - `401`: Invalid username or password.

### Verify JWT Token

- **Endpoint:** `/verify-token`
- **Method:** `GET`
- **Security:** Bearer Token
- **Responses:**
    - `200`: Token is valid.
    - `401`: Token is missing, invalid, or expired.

### Reset Password

- **Endpoint:** `/reset-password`
- **Method:** `POST`
- **Security:** Bearer Token
- **Request Body:**
    ```json
    {
        "current_password": "password123",
        "new_password": "newpassword123"
    }
    ```
- **Responses:**
    - `200`: Password reset successful.
    - `400`: Current password is incorrect or user does not exist.
    - `401`: Token is missing, invalid, or expired.

## Models

### User

- **Columns:**
  - `id`: Integer, primary key.
  - `username`: String(50), unique, not nullable.
  - `first_name`: String(50), not nullable.
  - `last_name`: String(50), not nullable.
  - `email`: String(120), unique, not nullable.
  - `password`: String(255), encrypted, not nullable.
  - `role`: Enum(User, Admin), default is `User`, not nullable.
  - `create_date`: DateTime, default is current timestamp.
  - `update_date`: DateTime, auto-updates on REST API call.
  - `active`: Boolean, default is `True`.

## Notes

- Ensure your PostgreSQL database is running and the connection details are correctly set in the configuration.
- The default admin user is created automatically if no users exist in the database.
- This project uses JWT for authentication. Ensure you keep your `SECRET_KEY` safe and secure.
