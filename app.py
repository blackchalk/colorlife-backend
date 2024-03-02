# app.py
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from bson import ObjectId
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/colorMapDB'
mongo = PyMongo(app)

# User model
class User:
    def __init__(self, email, password_hash):
        self.email = email
        self.password_hash = password_hash

# MongoDB collection
users_collection = mongo.db.users

# Middleware to verify JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'Email already exists'}), 400
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(email, password_hash)
    users_collection.insert_one(new_user.__dict__)
    return jsonify({'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = users_collection.find_one({'email': email})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
        return jsonify({'message': 'Invalid email or password'}), 401
    token = jwt.encode({'email': email}, app.config['SECRET_KEY'])
    return jsonify({'token': token.decode('UTF-8')}), 200

if __name__ == '__main__':
    app.run(debug=True)

