from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib

print("App is starting...")

app = Flask(__name__)
app.secret_key = "my_secret_key_123"
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT
    )
    ''')

    admin_pass = hash_password("admin123")

    c.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_pass, "admin")
        )

    conn.commit()
    conn.close()

init_db()
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute(
            "SELECT username, role FROM users WHERE username = ? AND password_hash = ?",
            (username, password)
        )
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = user[0]
            session['role'] = user[1]

            if user[1] == 'admin':
                return redirect('/admin')
            return redirect('/user')

        error = "Wrong username or password"

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            error = "All fields are required!"
        elif password != confirm_password:
            error = "Passwords do not match!"
        else:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = c.fetchone()

            if existing_user:
                error = "Username already exists!"
                conn.close()
            else:
                hashed_password = hash_password(password)
                c.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, hashed_password, "user")
                )
                conn.commit()
                conn.close()

               
                session['username'] = username
                session['role'] = 'user'

                return redirect('/user')

    return render_template('register.html', error=error)

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect('/')

    if session.get('role') != 'admin':
        return "Access denied! You are not an admin."

    return render_template('admin.html', username=session['username'])

@app.route('/user')
def user():
    if 'username' not in session:
        return redirect('/')

    return render_template('user.html', username=session['username'])
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None

    if request.method == 'POST':
        username = request.form['username']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            return redirect(f'/reset_password/{username}')
        else:
            error = "Username does not exist!"

    return render_template('forgot_password.html', error=error)

@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if not user:
        conn.close()
        return render_template(
            'message.html',
            title="Error",
            message="User not found!",
            link_url="/forgot_password",
            link_text="Try again",
            message_type="error"
        )

    if request.method == 'POST':
        new_password = hash_password(request.form['new_password'])
        c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password, username))
        conn.commit()
        conn.close()

        return render_template(
            'message.html',
            title="Success",
            message="Password reset successful!",
            link_url="/",
            link_text="Go back to login",
            message_type="success"
        )

    conn.close()
    return render_template('reset_password.html', username=username)

if __name__ == '__main__':
    import os

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)