from flask import Flask,request,render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
      username = request.form.get('username')
      password = request.form.get('password')
      repassword = request.form.get('repassword')
      if password != repassword:
        ('パスワードが一致しません')
      else:
        pass
      user = User.query.filter_by(username=username).first()
      if check_password_hash(user.password, password):
        login_manager('user')
        return redirect('/')
    else:
      return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # create user object
        new_user = User(
            username=request.form['username'],
            email=request.form['email'],
            password=request.form['password']
        )
        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        return 'User created successfully'
    else:
      return render_template('signup.html')

if __name__ == "__main__":
    app.run(debug=True)
