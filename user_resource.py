from flask import request
from flask_restful import Resource
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db  # Import User and db from models



class UserResource(Resource):
    """
    UserResource class handles user-related operations:
    - User registration
    - User login (authentication)
    - User profile retrieval
    - User profile update
    - User account deletion
    """


    def post(self):
        """
        Register a new user (handles POST method).
        """
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Validate input
        if not username or not password:
            return {"message": "Username and password are required"}, 400

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return {"message": "User already exists"}, 400

        # Hash the password
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)

        # Save the new user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            return {"message": "User registered successfully"}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": "An error occurred during registration"}, 500





    def login(self):
        """
        Authenticate a user and return a JWT token.
        Expected input (JSON):
        {
            "username": "string",
            "password": "string"
        }
        """
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Find the user in the database
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return {"message": "Invalid credentials"}, 401

        # Generate a JWT token
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token}, 200

    @jwt_required()
    def get_user(self, user_id):
        """
        Retrieve the user profile for the authenticated user.
        Requires JWT authentication.

        :param user_id: The ID of the user to retrieve
        """
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        # Ensure the current user can only access their own profile
        current_user_id = get_jwt_identity()
        if current_user_id != user.id:
            return {"message": "Unauthorized access"}, 403

        return {
            "id": user.id,
            "username": user.username,
            "created_at": user.created_at.strftime("%Y-%m-%d")
        }, 200

    @jwt_required()
    def update_user(self, user_id):
        """
        Update user profile information.
        Requires JWT authentication.
        Expected input (JSON):
        {
            "username": "string"
        }

        :param user_id: The ID of the user to update
        """
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        current_user_id = get_jwt_identity()
        if current_user_id != user.id:
            return {"message": "Unauthorized access"}, 403

        data = request.get_json()
        username = data.get('username')

        # Validate input
        if not username:
            return {"message": "Username is required"}, 400

        # Update username
        user.username = username

        try:
            db.session.commit()
            return {"message": "User updated successfully"}, 200
        except Exception as e:
            db.session.rollback()
            return {"message": "An error occurred while updating"}, 500

    @jwt_required()
    def delete(self, user_id):
        """
        Delete the user account.
        Requires JWT authentication.

        :param user_id: The ID of the user to delete
        """
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        current_user_id = get_jwt_identity()
        if current_user_id != user.id:
            return {"message": "Unauthorized access"}, 403

        try:
            db.session.delete(user)
            db.session.commit()
            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            db.session.rollback()
            return {"message": "An error occurred while deleting"}, 500
#jwt = JWTManager(app)  # Initialize JWT Manager

# Adding routes for the UserResource
#api.add_resource(UserResource, '/api/users', '/api/users/<int:user_id>', endpoint="user")

# Register resource to handle POST requests
#api.add_resource(UserResource, '/api/users', methods=['POST'])

#api.add_resource(UserResource, '/api/login', endpoint="login")    # New route for login



