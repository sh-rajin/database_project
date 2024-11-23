from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_bcrypt import Bcrypt
import pymysql

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# Database configuration
db = pymysql.connect(host="localhost", user="root", password="password", database="user_auth")
cursor = db.cursor()

# Routes
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            # Set session variable indicating the user is logged in
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid Username or Password!', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, password))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect('/login')
        except:
            flash('Username or email already exists.', 'danger')

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in (session variable exists)
    if 'user_id' not in session:
        flash('You must be logged in to access the dashboard.', 'danger')
        return redirect('/login')
    
    return render_template('dashboard.html',username = session['username'])

@app.route('/logout')
def logout():
    # Clear the session to log out the user
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
