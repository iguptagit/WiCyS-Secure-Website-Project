# app.py
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
from itsdangerous import URLSafeTimedSerializer
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Rate limiter: 5 login attempts per 15 minutes per IP (adjust for demo)
limiter = Limiter(
    key_func=get_remote_address, 
    default_limits=["10 per minute"]
)
limiter.init_app(app)

# Serializer for email tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# --- Simple user model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False)

# create DB
with app.app_context():
    db.create_all()

# --- helpers ---
def hash_password(plain_password: str) -> bytes:
    # bcrypt automatically salts; cost factor 12
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def check_password(plain_password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), pw_hash)

def password_policy_ok(pw: str) -> (bool, str):
    # simple policy: min 8 chars, at least one number, one letter
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[0-9]", pw):
        return False, "Password must include a number."
    if not re.search(r"[A-Za-z]", pw):
        return False, "Password must include a letter."
    return True, ""

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# --- routes ---
@app.route('/')
def index():
    return render_template('index.html', user_id=session.get('user_id'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        ok, msg = password_policy_ok(password)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "warning")
            return redirect(url_for('register'))
        pw_hash = hash_password(password)
        user = User(email=email, password_hash=pw_hash, is_confirmed=False)
        db.session.add(user)
        db.session.commit()
        # generate email token (mock send)
        token = serializer.dumps(email, salt='email-confirm')
        print(f"[MOCK EMAIL] Confirmation token for {email}: {token}")
        flash("Registered! (confirmation token printed to console for demo)", "success")
        return redirect(url_for('index'))
    return render_template('register.html')

# limit login to 10 attempts per 2 minutes per IP
@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per 2 minutes")
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password(password, user.password_hash):
            if not user.is_confirmed:
                flash("Please confirm your email first.", "warning")
                return redirect(url_for('login'))
            session['user_id'] = user.id
            flash("Logged in!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials", "danger")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # 1 hour
    except Exception:
        flash("Invalid or expired token", "danger")
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_confirmed = True
        db.session.commit()
        flash("Email confirmed! You can now login.", "success")
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return f"Secret page. Hello user {session['user_id']}"

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)