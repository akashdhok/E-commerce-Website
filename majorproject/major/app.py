import os
import time
import re
import pyotp
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Mail, Message

from function import apology, login_required

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

app.config["SECRET_KEY"] = os.urandom(24)

# Generate a random secret key for TOTP
app.config["TOTP_SECRET"] = pyotp.random_base32()

# Mail Config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "shivamoffice5122@gmail.com"
app.config["MAIL_PASSWORD"] = "meif liqg tuwi rhgw"

Session(app)
mail = Mail(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    free_pickle = db.execute("SELECT * FROM products WHERE price=?", 0)
    products = db.execute(
        "SELECT * FROM  products JOIN  color ON products.product_id = color.product_id WHERE NOT price=0"
    )
    return render_template("index.html", free_pickle=free_pickle, products=products)


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("phone"):
            mobile_error = "must provide mobile number or email"
            return render_template("login.html", mobile_error=mobile_error)
        # Ensure password was submitted
        elif not request.form.get("password"):
            password_error = "must provide password"
            return render_template("login.html", password_error=password_error)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE phone = ? OR email = ?",
            request.form.get("phone"),
            request.form.get("phone"),
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["password_hash"], request.form.get("password")
        ):
            error = "invalid mobile number and/or password."
            return render_template("/login.html", error=error)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


def generate_totp():
    totp = pyotp.TOTP(app.config["TOTP_SECRET"])
    return totp.now()


@app.route("/verification", methods=["GET", "POST"])
def verification():
    if request.method == "POST":
        otp = request.form.get("otp")
        totp = session.get("totp")

        if totp is None or not otp:
            return redirect("/verification")

        if totp == otp:
            username = session["username"]
            phone = session["phone"]
            email = session["email"]
            password = session["password"]

            # generating the hash of password
            password_hash = generate_password_hash(password)

            db.execute(
                "INSERT INTO users (username,phone,email,password_hash,created_at) VALUES(?,?,?,?,?)",
                username,
                phone,
                email,
                password_hash,
                datetime.datetime.now(),
            )

            session.clear()

            return redirect("/login")
        else:
            return render_template("verification", otp_error="Invalid OTP. Try again.")
    # Generate and store TOTP in the session
    session["totp"] = generate_totp()
    print("===============================================", session["totp"])
    if session["email"]:
        subject = "Verification code"
        otp = session["totp"]
        body = f"This is your verification code:{otp}"
        sender_email = "shivamoffice5122@gmail.com"

        try:
            msg = Message(subject, sender=sender_email, recipients=[session["email"]])
            msg.body = body
            mail.send(msg)
            print("=============================Success=========================")
        except Exception as e:
            print(f"Error sending email: {str(e)}", "error")
    return render_template("verification.html")


# Registration of user and it's form vaildation
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Getting username,phonr number,email,password and confirm password from the form
        username = request.form.get("username")
        phone = request.form.get("phone")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        session.clear()

        session["username"] = username
        session["phone"] = phone
        session["email"] = email
        session["password"] = password

        # Checking if the feild of form is blank

        blank = []

        if not username:
            blank.append("username")

        if not phone:
            blank.append("phone")

        if not email:
            blank.append("email")

        if not password:
            blank.append("password")
            blank.append("confirm_password")

        if not confirm_password:
            blank.append("confirm_password")

        if len(blank) > 0:
            return render_template("register.html", blank=blank)

        if password != confirm_password:
            password_error = "Password did not matched"
            return render_template("register.html", password_error=password_error)

        pattern = re.compile(r"^\d{10}$")
        if not re.match(pattern, phone):
            return render_template("register.html", phone_error="Invaild number")

        # Search in database if user already exist with phone number
        user = db.execute(
            "SELECT phone FROM users WHERE phone=? OR email=?", phone, email
        )

        if len(user) != 0:
            error = "User already exits!"
            return render_template("register.html", error=error)

        return redirect("/verification")

    return render_template("register.html")


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        search = request.form.get("search")
        products = db.execute(
            "SELECT * FROM products WHERE name LIKE ? AND NOT price=0",
            "%" + search + "%",
        )
    return render_template("search.html", products=products)


@app.route("/product_detail/<int:product_id>")
def product(product_id):
    product_detail = db.execute("SELECT * FROM products WHERE product_id=?", product_id)
    reviews = db.execute("SELECT * FROM reviews WHERE product_id=?", product_id)
    return render_template(
        "product_detail.html", product_detail=product_detail, reviews=reviews
    )


@app.route("/order/<int:id>", methods=["GET", "POST"])
@login_required
def order(id):
    if request.method == "POST":
        address = request.form.get("address")
        city = request.form.get("city")
        state = request.form.get("state")
        pin_code = request.form.get("pin_code")

        db.execute(
            "INSERT INTO address(user_id,address,city,state,pin_code) VALUES(?,?,?,?,?)",
            session["user_id"],
            address,
            city,
            state,
            pin_code,
        )

        return redirect(f"/order/{id}")

    user_address = db.execute(
        "SELECT * FROM address WHERE user_id=?", session["user_id"]
    )
    if len(user_address) == 0:
        return render_template("order.html", product_id=id)
    return render_template("order.html", user_address=user_address, product_id=id)


@app.route("/add_to_cart/<int:product_id>")
@login_required
def add_to_cart(product_id):
    products = db.execute("SELECT * FROM products WHERE product_id=?", product_id)
    product = next((p for p in products if p["product_id"] == product_id), None)

    if product:
        session.setdefault("cart", [])
        session["cart"].append(
            {"id": product_id, "name": product["name"], "price": product["price"]}
        )
        print("========================sucsses====================")

    return redirect("/")


@app.route("/cart")
@login_required
def cart():
    cart = session.get("cart", [])
    print(cart)
    return render_template("cart.html", cart=cart)


@app.route("/remove_from_cart/<int:product_id>")
@login_required
def remove_from_cart(product_id):
    cart = session.get("cart", [])
    session["cart"] = [item for item in cart if item["id"] != product_id]
    return redirect("/cart")


@app.route("/remove_all_from_cart")
@login_required
def remove_all_from_cart():
    session["cart"].clear()
    return redirect("/cart")


@app.route("/address_edit/<int:product_id>", methods=["POST"])
@login_required
def address_edit(product_id):
    address = request.form.get("address")
    city = request.form.get("city")
    state = request.form.get("state")
    pin_code = request.form.get("pin_code")

    db.execute(
        "UPDATE address SET address=? ,city=? ,state=? ,pin_code=? WHERE user_id=?",
        address,
        city,
        state,
        pin_code,
        session["user_id"],
    )

    return redirect(f"/order/{product_id}")


@app.route("/delete_address/<int:product_id>", methods=["GET", "POST"])
@login_required
def delete_address(product_id):
    db.execute("DELETE FROM address WHERE user_id=?", session["user_id"])
    return redirect(f"/order/{product_id}")


@app.route("/products")
def products():
    products = db.execute(
        "SELECT * FROM  products JOIN  color ON products.product_id = color.product_id WHERE NOT price=0"
    )
    return render_template("products.html", products=products)


@app.route("/insert", methods=["GET", "POST"])
def insert():
    if request.method == "POST":
        product_id = request.form.get("product_id")
        name = request.form.get("name")
        description = request.form.get("description")
        price = request.form.get("price")
        category_id = request.form.get("category_id")

        db.execute(
            "INSERT INTO products(product_id,name,description,price,category_id) VALUES(?,?,?,?,?)",
            product_id,
            name,
            description,
            price,
            category_id,
        )
        return render_template("insert_product.html")

    return render_template("insert_product.html")


@app.route("/review_post/<int:product_id>", methods=["GET", "POST"])
@login_required
def review(product_id):
    if request.method == "POST":
        review = request.form.get("review")

        user_name = (
            db.execute(
                "SELECT username FROM users WHERE user_id=?", session["user_id"]
            )[0]
        )["username"]

        db.execute(
            "INSERT INTO reviews(product_id,username,review) VALUES(?,?,?)",
            product_id,
            user_name,
            review,
        )

        return redirect(f"/product_detail/{product_id}")


@app.route("/account")
@login_required
def account():
    return render_template("account.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email_phone = request.form.get("email_phone")
        user = db.execute(
            "SELECT * FROM users WHERE email=? OR phone=?", email_phone, email_phone
        )

        if len(user) != 0:
            session["totp"] = generate_totp()
            session["email"] = (user[0])["email"]
            subject = "Verification code for password reset"
            otp = session["totp"]
            body = f"This is your password reset verification code:{otp}"
            sender_email = "shivamoffice5122@gmail.com"

            try:
                msg = Message(
                    subject, sender=sender_email, recipients=[(user[0])["email"]]
                )
                msg.body = body
                mail.send(msg)
            except Exception as e:
                print(f"Error sending email: {str(e)}", "error")

            return redirect("/password_reset_verification")
        else:
            return render_template(
                "/forgot_password.html",
                forgot_password_error="User not found with is email/phone number.",
            )

    return render_template("/forgot_password.html")


@app.route("/password_reset_verification", methods=["GET", "POST"])
def password_reset_verification():
    if request.method == "POST":
        otp = request.form.get("otp")
        totp = session["totp"]

        if totp is None or not otp:
            return redirect("/verification_reset_password", otp_error="Invaild otp")

        if otp == totp:
            return redirect("/change_password")
        else:
            return render_template(
                "verification_reset_password.html", otp_error="Invaild otp"
            )

    return render_template("verification_reset_password.html")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            return render_template("change_password.html", error="Can't be blank")

        if new_password != confirm_password:
            return render_template(
                "change_password.html", confirm_password_error="Password did'nt match"
            )

        hash_new_password = generate_password_hash(new_password)

        db.execute(
            "UPDATE users SET password_hash=? WHERE email=?",
            hash_new_password,
            session["email"],
        )

        session.clear()

        return redirect("/login")

    return render_template("change_password.html")

@app.route("/contect", methods=["GET"])
def contect():
    return render_template("contectus.html")

@app.route("/your_orders", methods=["GET", "POST"])
@login_required
def your_orders():
    if request.method == "GET":
        return render_template("yourorder.html")
    
@app.route("/security", methods=["GET", "POST"])
@login_required
def security():
    if request.method == "GET":
        user =  db.execute("SELECT * FROM users WHERE user_id= ?", session["user_id"])
        return render_template("security.html", user=user)
    if request.method == "POST":
        username = request.form.get("username")
        db.execute(
            "UPDATE users SET username=? WHERE user_id=?", username,session["user_id"]
        )
        return redirect("/security")
    
@app.route("/youraddress", methods=["GET", "POST"])
@login_required
def your_address():
    if request.method == "GET":
        address = db.execute(
            "SELECT * FROM address WHERE user_id=?",session["user_id"]
        )
        print(address)
        return render_template("youraddress.html", address=address)
    if request.method == "POST":
        address = request.form.get("address")
        city = request.form.get("city")
        state = request.form.get("state")
        pin_code = request.form.get("pin_code")
        db.execute(
            "UPDATE address SET address=? ,city=? ,state=? ,pin_code=? WHERE user_id=?",
        address,
        city,
        state,
        pin_code,
        session["user_id"],
        )
    return redirect("/youraddress")