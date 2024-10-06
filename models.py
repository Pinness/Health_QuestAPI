from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
#from database import Base, User, Category, Quiz, Question, Answer, UserResponse, SessionLocal
from os import getenv # Helps to get the environmental variables
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Getting the secret key
app.secret_key = getenv('FLASK_SECRET_KEY')

# Construct the database URI
db_url = getenv('SQLALCHEMY_DATABASE_URI')

# Creating the database instance
app.config['SQLALCHEMY_DATABASE_URI'] = db_url  #Instantiates the database connectionConfigure sqlalchemy to work with f# Construct the database URI
db_url = getenv('SQLALCHEMY_DATABASE_URI')


# Construct the database URI
#db_url = getenv('SQLALCHEMY_DATABASE_URI')

db = SQLAlchemy(app)

class User(db.Model, UserMixin):  # Inherit UserMixin
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)


