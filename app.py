from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask import abort
from functools import wraps
import secrets
from datetime import timedelta
from flask import session
from datetime import datetime

app = Flask(__name__)
# app.secret_key = 'your_secret_key'  # Nahraďte vlastním tajným klíčem 
app.secret_key = secrets.token_hex(16)
bcrypt = Bcrypt(app)

app.permanent_session_lifetime = timedelta(minutes=1)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Možná budete chtít použít 'REMEMBER_COOKIE_DURATION' k nastavení času pro automatické odhlášení
login_manager.remember_cookie_duration = timedelta(minutes=1)

# Databáze uživatelů (pro jednoduchost hardcoded, použijte databázi pro produkci)
users = {
    "admin": {"password": bcrypt.generate_password_hash("adminpass").decode('utf-8'), "role": "admin"},
    "user": {"password": bcrypt.generate_password_hash("userpass").decode('utf-8'), "role": "user"},
    "footballer": {"password": bcrypt.generate_password_hash("fpass").decode('utf-8'), "role": "footballer"},
    "Michal": {"password": bcrypt.generate_password_hash("Ostrava").decode('utf-8'), "role": "author"},
}


@app.before_request
def track_user_activity():
    # Získání času poslední aktivity
    session['last_activity'] = datetime.now()


@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        elapsed_time = datetime.now() - session['last_activity']
        if elapsed_time > timedelta(minutes=1):
            logout_user()
            session.clear()
            flash("Byl jste odhlášen z důvodu neaktivity.", "warning")
            return redirect(url_for('login'))

# Třída User
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

# Načítání uživatele
@login_manager.user_loader
def load_user(username):
    user = users.get(username)
    if user:
        return User(username, user["role"])
    return None

@app.route('/')
def index():
    return "Domovská stránka. <a href='/login'>Přihlásit se</a>"

# Vlastní dekorátor pro kontrolu rolí
# def role_required(role):
#      def decorator(func):
#          @login_required
#          def wrapper(*args, **kwargs):
#              if current_user.role != role:
#                 abort(403)  # HTTP Forbidden
#              return func(*args, **kwargs)
#          return wrapper
#      return decorator

def role_required(*roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)  # Forbidden
            return func(*args, **kwargs)
        return wrapper
    return decorator

# def role_required(*roles):
#     def decorator(func):
#         @login_required  # Nejdříve ověř, že je uživatel přihlášen
#         def wrapper(*args, **kwargs):
#             if current_user.role not in roles:  # Pokud uživatel nemá požadovanou roli
#                 flash("Nemáte dostatečná oprávnění pro přístup k této stránce.", "danger")
#                 return redirect(url_for('login'))  # Přesměrování na přihlašovací stránku
#             return func(*args, **kwargs)
#         return wrapper
#     return decorator


@app.route('/login', methods=['GET', 'POST'])
def login():

    session.permanent = True

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and bcrypt.check_password_hash(user['password'], password):
            # session['user'] = user
            login_user(User(username, user["role"]))
            session.permanent = True  # Nastavení session jako permanen
            flash("Přihlášení úspěšné!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Nesprávné uživatelské jméno nebo heslo.", "danger")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Odhlášení úspěšné!", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
# @role_required('admin','user','footballer')
def dashboard():
    if current_user.role == "admin":
        return render_template('admin.html', user=current_user)
    elif current_user.role == "user":
        return render_template('user.html', user=current_user)
    elif current_user.role == "footballer":
        return render_template('f.html', user=current_user)
    else:
        return "Neznámá role.", 403
    

# Stránka přístupná pouze adminům
@app.route('/a')
@role_required('admin','user')
# def admin_page():
#       return "Admin stránka - přístupná pouze adminům."
def admin_page():    
    return render_template('a.html', user=current_user)
    # abort(403)
    

# Stránka přístupná pouze běžným uživatelům
@app.route('/user')
@login_required
@role_required('user')
def user_page():

    if not current_user.is_authenticated:
        logout_user()  # Odhlášení uživatele
        session.clear()  # Vymazání session
        return redirect(url_for('login'))
    
    # return "Stránka pro uživatele - přístupná pouze běžným uživatelům."
    return render_template('user.html', user=current_user)

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True)

