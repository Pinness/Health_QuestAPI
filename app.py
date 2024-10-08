# app.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize the app
app = Flask(__name__)

# Configuration
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable track modifications for performance

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
api = Api(app)

# Import models
from models import User  # Import User model after initializing db

# Import resources
from user_resource import UserResource  # Assuming UserResource is defined in user_resource.py

# Add resources
api.add_resource(UserResource, '/api/users', methods=['POST'])
api.add_resource(UserResource, '/api/login', endpoint="login")

if __name__ == "__main__":
    # Create the database tables if they do not exist
    #with app.app_context():
        #db.create_all()  # Create all tables
    app.run(debug=True)

