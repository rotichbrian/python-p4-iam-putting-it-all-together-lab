
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
import os

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False, default=lambda: bcrypt.generate_password_hash(os.urandom(16)).decode('utf-8'))
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    recipes = db.relationship('Recipe', backref='user')

    @validates('_password_hash')
    def validate_password_hash(self, key, password_hash):
        if not password_hash:
            raise ValueError("Password hash must not be empty.")
        return password_hash

    @hybrid_property
    def password_hash(self):
        raise AttributeError('password is not a readable attribute')

    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password must not be empty.")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def set_password(self, password):
        if not password:
            raise ValueError("Password must not be empty.")
        self.password_hash = password

    def check_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    def authenticate(self, password):
        return self.check_password(password)
    
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions
