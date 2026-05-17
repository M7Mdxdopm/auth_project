import sqlite3
import hashlib
import re
from flask import Flask, request, redirect, session, render_template, url_for

app = Flask(__name__)
app.secret_key = "my_secret_key_123"

DB_NAME = "database.db"


# ---------------- REGEX RULES ----------------

FIRST_LAST_NAME_REGEX = r"^[A-Z][a-zA-Z]{1,29}$"
ISRAELI_ID_REGEX = r"^\d{9}$"
CREDIT_CARD_REGEX = r"^\d{4}\s\d{4}\s\d{4}\s\d{4}$"
VALID_DATE_REGEX = r"^(0[1-9]|1[0-2])\/\d{2}$"
CVC_REGEX = r"^\d{3}$"


# ---------------- HELPERS ----------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_db():
    return sqlite3.connect(DB_NAME)


def is_valid_credit_card_data(first_name, last_name, israeli_id, card_number, valid_date, cvc):
    return (
        re.fullmatch(FIRST_LAST_NAME_REGEX, first_name) and
        re.fullmatch(FIRST_LAST_NAME_REGEX, last_name) and
        re.fullmatch(ISRAELI_ID_REGEX, israeli_id) and
        re.fullmatch(CREDIT_CARD_REGEX, card_number) and
        re.fullmatch(VALID_DATE_REGEX, valid_date) and
        re.fullmatch(CVC_REGEX, cvc)
    )


# ---------------- DATABASE ----------------

def create_users_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            israeli_id TEXT NOT NULL,
            credit_card_number TEXT NOT NULL,
            valid_date TEXT NOT NULL,
            cvc TEXT NOT NULL
        )
    """)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    create_users_table(cursor)

    users = [
        ("admin", "Admin123!", "admin", "Israeli", "Israeili", "123456789", "1234 5567 8901 2345", "12/32", "123"),
        ("user1", "User123!", "user", "David", "Cohen", "111111111", "1111 2222 3333 4444", "11/30", "111"),
        ("user2", "User123!", "user", "Yossi", "Levi", "222222222", "2222 3333 4444 5555", "10/31", "222"),
        ("user3", "User123!", "user", "Moshe", "Mizrahi", "333333333", "3333 4444 5555 6666", "09/32", "333"),
        ("user4", "User123!", "user", "Avi", "Peretz", "444444444", "4444 5555 6666 7777", "08/33", "444"),
        ("user5", "User123!", "user", "Noam", "Biton", "555555555", "5555 6666 7777 8888", "07/34", "555"),
        ("user6", "User123!", "user", "Omer", "Azulai", "666666666", "6666 7777 8888 9999", "06/35", "666"),
        ("user7", "User123!", "user", "Lior", "Malka", "777777777", "7777 8888 9999 0000", "05/36", "777"),
        ("user8", "User123!", "user", "Daniel", "Amar", "888888888", "8888 9999 0000 1111", "04/37", "888"),
        ("user9", "User123!", "user", "Eli", "Barak", "999999999", "9999 0000 1111 2222", "03/38", "999"),
    ]

    for username, password, role, first_name, last_name, israeli_id, card, date, cvc in users:
        cursor.execute("""
            INSERT OR IGNORE INTO users
            (username, password_hash, role, first_name, last_name, israeli_id, credit_card_number, valid_date, cvc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username,
            hash_password(password),
            role,
            first_name,
            last_name,
            israeli_id,
            card,
            date,
            cvc
        ))

    conn.commit()
    conn.close()


# ---------------- SECURE LOGIN ----------------

@app.route("/", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, role
            FROM users
            WHERE username = ? AND password_hash = ?
        """, (username, password_hash))

        user = cursor.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[2]

            if user[2] == "admin":
                return redirect("/admin")
            return redirect("/user")

        error = "Wrong username or password"

    return render_template("login.html", error=error)


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        israeli_id = request.form["israeli_id"]
        card_number = request.form["credit_card_number"]
        valid_date = request.form["valid_date"]
        cvc = request.form["cvc"]

        if password != confirm_password:
            error = "Passwords do not match"

        elif not is_valid_credit_card_data(first_name, last_name, israeli_id, card_number, valid_date, cvc):
            error = "Invalid fields. Check first name, last name, ID, credit card, valid date, and CVC."

        else:
            try:
                conn = get_db()
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO users
                    (username, password_hash, role, first_name, last_name, israeli_id, credit_card_number, valid_date, cvc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    username,
                    hash_password(password),
                    "user",
                    first_name,
                    last_name,
                    israeli_id,
                    card_number,
                    valid_date,
                    cvc
                ))

                conn.commit()
                conn.close()

                return render_template(
                    "message.html",
                    title="Registration Successful",
                    message="Your account was created successfully.",
                    message_type="success",
                    link_url="/",
                    link_text="Back to Login"
                )

            except sqlite3.IntegrityError:
                error = "Username already exists"

    return render_template("register.html", error=error)


# ---------------- ADMIN PAGE ----------------

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, role, first_name, last_name, israeli_id,
               credit_card_number, valid_date, cvc
        FROM users
        ORDER BY id ASC
    """)

    users = cursor.fetchall()
    conn.close()

    return render_template(
        "admin.html",
        username=session.get("username"),
        users=users
    )


# ---------------- USER PAGE ----------------

@app.route("/user")
def user():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, role, first_name, last_name, israeli_id,
               credit_card_number, valid_date, cvc
        FROM users
        WHERE id = ?
    """, (session["user_id"],))

    user_data = cursor.fetchone()
    conn.close()

    return render_template(
        "user.html",
        username=session.get("username"),
        user_data=user_data
    )


# ---------------- SQL INJECTION DEMO LOGIN ----------------
# This route is intentionally vulnerable for the classwork demo only.

@app.route("/vuln_login", methods=["GET", "POST"])
def vuln_login():
    error = ""
    shown_query = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hash_password(password)

        conn = get_db()
        cursor = conn.cursor()

        shown_query = f"""
            SELECT id, username, role
            FROM users
            WHERE username = '{username}' AND password_hash = '{password_hash}'
        """

        try:
            cursor.execute(shown_query)
            user = cursor.fetchone()
        except sqlite3.Error as e:
            user = None
            error = f"SQL Error: {e}"

        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[2]

            if user[2] == "admin":
                return redirect("/admin")
            return redirect("/user")

        if not error:
            error = "Login failed"

    return render_template(
        "vuln_login.html",
        error=error,
        shown_query=shown_query
    )


# ---------------- FORGOT PASSWORD ----------------

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    error = ""

    if request.method == "POST":
        username = request.form["username"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username
            FROM users
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()
        conn.close()

        if user:
            return redirect(url_for("reset_password", username=username))

        error = "Username does not exist"

    return render_template("forgot_password.html", error=error)


@app.route("/reset_password/<username>", methods=["GET", "POST"])
def reset_password(username):
    error = ""
    success = ""

    if request.method == "POST":
        new_password = request.form["new_password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
        """, (hash_password(new_password), username))

        conn.commit()
        conn.close()

        success = "Password was reset successfully."

    return render_template(
        "reset_password.html",
        username=username,
        error=error,
        success=success
    )


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- RUN APP ----------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)