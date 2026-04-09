import os
from flask import Flask, render_template, request, redirect, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import RegistrationForm, UpdateForm, LoginForm
from functools import wraps

# Task 1 & 2 & 3 & 4 Imports
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv() # Loads variables from .env into the system (Task 4)

app = Flask(__name__)

# Task 1: Security Headers
Talisman(app, content_security_policy=None, force_https=False)

# Task 2: Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Task 4: Environmental Secret Management
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default_fallback_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site_new.db')

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', admin='{self.is_admin}')"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

with app.app_context():
    db.create_all()

@app.route("/", methods=["GET", "POST"])
def hello_world():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if not existing_user:
            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_pw, is_admin=form.is_admin.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect("/")

    allpeople = User.query.all()

    return render_template("index.html", allpeople=allpeople, form=form)

@app.route("/home")
def home():
    return "<p>Welcome to the Home Page!</p>"

@app.route("/delete/<int:id>")
@admin_required
def delete(id):
    user_to_delete = User.query.get_or_404(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect("/")

@app.route("/update/<int:id>", methods=["GET","POST"])
@admin_required
def update(id):
    user = User.query.get_or_404(id)
    form = UpdateForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        return redirect("/")

    return render_template("update.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Only 5 attempts allowed per minute per IP
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login Successful!', 'success')
            return redirect("/")
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

# Task 3: Secure File Upload requirements
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == "":
            flash("No file selected", "danger")
            return redirect("/upload")
        
        # Securing the upload
        if allowed_file(file.filename):
            # secure_filename removes paths like ../../etc/passwd
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash(f"File {filename} successfully secured and uploaded!", "success")
            return redirect("/upload")
        else:
            flash("File type not allowed or malicious file disguised!", "danger")
            return redirect("/upload")
            
    return render_template('upload.html')

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Rate limit exceeded. Too many requests! Wait a moment.", 429

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    app.run(debug=False)
