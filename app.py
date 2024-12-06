from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# app.secret_key = 'your_secret_key'  # Nahraďte vlastním tajným klíčem 
app.secret_key = 'Ostrava'  # Nahraďte vlastním tajným klíčem
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Databáze uživatelů (pro jednoduchost hardcoded, použijte databázi pro produkci)
users = {
    "admin": {"password": bcrypt.generate_password_hash("adminpass").decode('utf-8'), "role": "admin"},
    "user": {"password": bcrypt.generate_password_hash("userpass").decode('utf-8'), "role": "user"},
}

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


# # Vlastní dekorátor pro kontrolu rolí
# def role_required(role):
#     def decorator(func):
#         @login_required
#         def wrapper(*args, **kwargs):
#             if current_user.role != role:
#                 abort(403)  # HTTP Forbidden
#             return func(*args, **kwargs)
#         return wrapper
#     return decorator


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(username, user["role"]))
            flash("Přihlášení úspěšné!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Nesprávné uživatelské jméno nebo heslo.", "danger")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Odhlášení úspěšné!", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == "admin":
        return render_template('admin.html', user=current_user)
    elif current_user.role == "user":
        return render_template('user.html', user=current_user)
    else:
        return "Neznámá role.", 403
    

# # Stránka přístupná pouze adminům
# @app.route('/admin')
# @role_required('admin')
# def admin_page():
#     return "Admin stránka - přístupná pouze adminům."

# # Stránka přístupná pouze běžným uživatelům
# @app.route('/user')
# @role_required('user')
# def user_page():
#     return "Stránka pro uživatele - přístupná pouze běžným uživatelům."

if __name__ == '__main__':
    app.run(debug=True)