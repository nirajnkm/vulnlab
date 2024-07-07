from flask import Flask, request, render_template, redirect, session, abort
from flask_pymongo import PyMongo
import bcrypt
from dotenv import load_dotenv
from functools import wraps
import os

load_dotenv()

app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.secret_key = os.getenv('SECRET_KEY')

mongo = PyMongo(app)

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'email' not in session:
                return redirect('/login')
            user = mongo.db.users.find_one({'email': session['email']})
            if not user or user['role'] not in allowed_roles:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

# Vulnerable registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')  # Vulnerable: allows role selection

        if not name or not email or not password:
            return render_template('register.html', error='Please fill in all the fields')

        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return render_template('register.html', error='User already exists')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role
        }

        mongo.db.users.insert_one(new_user)
        return redirect('/login')

    return render_template('register.html')

# Secure registration
@app.route('/secure_register', methods=['GET', 'POST'])
def secure_register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'user'  # Secure: role is always set to 'user'

        if not name or not email or not password:
            return render_template('secure_register.html', error='Please fill in all the fields')

        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return render_template('secure_register.html', error='User already exists')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role
        }

        mongo.db.users.insert_one(new_user)
        return redirect('/login')

    return render_template('secure_register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['email'] = user['email']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect('/admindashboard')
            else:
                return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid email or password')

    return render_template('login.html')

@app.route('/admindashboard')
def admindashboard():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        if user and user['role'] == 'admin':
            return render_template('admindashboard.html', user=user)
    return redirect('/login')

@app.route('/secure_admindashboard')
@role_required(['admin'])
def secure_admindashboard():
    user = mongo.db.users.find_one({'email': session['email']})
    return render_template('secure_admindashboard.html', user=user)

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = mongo.db.users.find_one({'email': session['email']})
        return render_template('dashboard.html', user=user)
    return redirect('/login')

@app.route('/secure_dashboard')
@role_required(['user', 'admin'])
def secure_dashboard():
    user = mongo.db.users.find_one({'email': session['email']})
    return render_template('secure_dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)  