#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()
        required_fields = ['username', 'password', 'image_url', 'bio']
        if not all(field in data for field in required_fields):
            missing_fields = ", ".join([field for field in required_fields if field not in data])
            return {"error": f"Missing fields: {missing_fields}"}, 422
        
        try:
            user = User(
                username=data['username'],
                image_url=data['image_url'],
                bio=data['bio']
            )
            user.set_password(data['password'])
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already exists or other integrity error"}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        user = db.session.get(User, user_id)
        if not user:
            return {"error": "User not found"}, 404
        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            session['user_id'] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        return {"error": "Invalid credentials"}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.pop('user_id', None)
        if not user_id:
            return {"error": "No user to log out"}, 401
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        print("Fetching user id from session...")
        user_id = session.get('user_id')
        if not user_id:
            print("No user id found in session")
            return {"error": "Unauthorized"}, 401
        try:
            print("Querying recipes for user id:", user_id)
            recipes = Recipe.query.filter_by(user_id=user_id).all()
            if not recipes:
                print("No recipes found for user id:", user_id)
                return {"error": "No recipes found"}, 404  # Consider returning 404 if no recipes are found
            print("Building JSON response...")
            response = [{
                "title": r.title,
                "instructions": r.instructions,
                "minutes_to_complete": r.minutes_to_complete,
                "user": {
                    "id": r.user.id if r.user else None,
                    "username": r.user.username if r.user else "Unknown"
                }
            } for r in recipes]
            print("Returning response...")
            return response, 200
        except Exception as e:
            print("Error fetching recipes:", str(e))
            return {"error": "Server error"}, 500
    
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            app.logger.error('Unauthorized access attempt.')
            return {"error": "Unauthorized"}, 401

        data = request.get_json(force=True)
        if not all(k in data for k in ('title', 'instructions', 'minutes_to_complete')):
            app.logger.error('Missing required fields: {}'.format(data))
            return {"error": "Missing required recipe fields"}, 422

        try:
            if len(data['instructions']) < 50:
                raise ValueError("Instructions must be at least 50 characters long.")
            
            if not data.get('title') or not data.get('instructions') or not data.get('minutes_to_complete'):
                raise ValueError("All fields must be provided.")

            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return {
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username
                }
            }, 201
        except ValueError as ve:
            app.logger.error(f'Validation error on creating recipe: {str(ve)}')
            return {"error": str(ve)}, 422
        except IntegrityError as ie:
            db.session.rollback()
            app.logger.error(f'IntegrityError on creating recipe: {str(ie)}')
            return {"error": "Database error, could not create recipe"}, 422
        except Exception as e:
            app.logger.error(f'Unexpected error on creating recipe: {str(e)}')
            return {"error": "Server error"}, 500

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)