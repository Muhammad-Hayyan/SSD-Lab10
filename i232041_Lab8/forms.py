from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Regexp

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=2, max=20), 
        Regexp('^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, or underscores")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    is_admin = BooleanField('Register as Admin', default=False)
    submit = SubmitField('Sign Up')

class UpdateForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=2, max=20), 
        Regexp('^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, or underscores")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
