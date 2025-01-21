# routes.py

import os
from flask import Blueprint, jsonify, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app.models import db, User, Course
from app import create_app

app = create_app()

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    @staticmethod
    def validate_username(username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    @staticmethod
    def validate_email(email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class CourseForm(FlaskForm):
    course_name = StringField('Course Name', validators=[DataRequired()])
    course_description = StringField('Course Description', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/')
def index():
    template_path = os.path.join(app.template_folder, 'index.html')
    print(f"Template path: {template_path}")
    if os.path.exists(template_path):
        return render_template('index.html')
    else:
        return "Template not found", 404



    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields.'}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'error': 'Username already registered.'}), 400

    user = User(username=username, email=email, role='student')
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, role='student')
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations! You are now registered!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/courses', methods=['GET'])
@login_required
def api_get_courses():
    courses = Course.query.all()
    return jsonify([{'course_id': course.course_id, 'course_name': course.course_name, 'course_description': course.course_description, 'instructor_id': course.instructor_id} for course in courses])

@app.route('/courses', methods=['GET'])
@login_required
def get_courses():
    courses = Course.query.all()
    return jsonify([course.title for course in courses])

@app.route('/test-static')
def test_static():
    return app.send_static_file('css/styles.css')

