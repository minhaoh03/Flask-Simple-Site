from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, login_user, logout_user, current_user
from sqlalchemy import true
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pw')
        confpassword = request.form.get('confpw')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            flash('Email already exists.', category='ERROR')
        elif len(email) < 4:
            flash('Invalid Email: Email must be greater than 4 characters.', category='ERROR')
        elif len(password) < 6:
            flash('Invalid Password: Password must be at least 6 or more characters.', category='ERROR')
        elif password != confpassword:
            flash('Invalid Confirmation: Passwords do not match.', category='ERROR')
        else:
            newUser = User(email=email, password=generate_password_hash(password, method='sha256'))
            db.session.add(newUser)
            db.session.commit()
            login_user(newUser)
            flash('Account created!', category='SUCCESS')
            return redirect(url_for('views.home'))
        
    return render_template("signup.html")

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pw')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='SUCCESS')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password', category='ERROR')
        else:
            flash('No user with that email', category='ERROR')

    return render_template("login.html")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))