import hmac
import logging
import math
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from html import escape

import pymysql
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_mail import Mail, Message
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------
SITE_NAME = "Multicloud Devops by Veera Sir Nareshit Microservices Ecommerce website"

# CORS: Nginx serves the frontend and /api from the same origin, so CORS is not
# needed. Set CORS_ORIGIN to your site (https://example.com) only if the
# browser calls this backend directly from another origin. "*" = allow all.
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")

# Auth tokens. Login always returns a signed token (if SECRET_KEY is set).
# Set AUTH_REQUIRED=true once the frontend sends "Authorization: Bearer <token>"
# on every request; the API then refuses access to other people's data.
SECRET_KEY = os.getenv("SECRET_KEY", "")
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").lower() == "true"
TOKEN_MAX_AGE = int(os.getenv("TOKEN_MAX_AGE_SECONDS", str(24 * 3600)))
if AUTH_REQUIRED and not SECRET_KEY:
    raise RuntimeError("AUTH_REQUIRED=true needs SECRET_KEY in the .env file")
serializer = URLSafeTimedSerializer(SECRET_KEY) if SECRET_KEY else None

# EC2 runs in UTC. Day boundaries ("OTP once per day") use this offset instead.
APP_TZ = timezone(timedelta(hours=float(os.getenv("TZ_OFFSET_HOURS", "5.5"))))

LOGIN_OTP_MINUTES = 5
SIGNUP_OTP_MINUTES = 10
OTP_RESEND_SECONDS = 30
OTP_MAX_ATTEMPTS = 5
MAX_QUANTITY = 100
MAX_AMOUNT = 10_000_000

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?\d{7,15}$")

db_config = {
    "host": os.getenv("DB_HOST", ""),
    "user": os.getenv("DB_USER", ""),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cloud"),
}

app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", ""),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", ""),
)
mail = Mail(app)


# ----------------------------------------------------------------------------
# CORS
# ----------------------------------------------------------------------------
@app.before_request
def handle_cors_preflight():
    if CORS_ORIGIN and request.method == "OPTIONS":
        return "", 204


@app.after_request
def add_cors_headers(response):
    if CORS_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ----------------------------------------------------------------------------
# Errors: details go to the log, users get a short safe message
# ----------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@app.errorhandler(ApiError)
def handle_api_error(exc):
    return jsonify({"error": str(exc)}), exc.status


@app.errorhandler(pymysql.err.OperationalError)
def handle_db_unavailable(exc):
    app.logger.exception("Database connection problem")
    return jsonify({"error": "Service temporarily unavailable. Please try again."}), 503


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    if isinstance(exc, HTTPException):
        return jsonify({"error": exc.description}), exc.code
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Something went wrong. Please try again."}), 500


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
def get_db_connection():
    return pymysql.connect(
        host=db_config["host"],
        user=db_config["user"],
        password=db_config["password"],
        database=db_config["database"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=5,
    )


@contextmanager
def db_session():
    """Yield (connection, cursor); always close. Uncommitted work is rolled back."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            yield conn, cursor
    finally:
        conn.close()


# ----------------------------------------------------------------------------
# Input helpers
# ----------------------------------------------------------------------------
def now():
    return datetime.now(APP_TZ).replace(tzinfo=None)


def get_json_payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def require_fields(data, fields):
    missing = []
    for field in fields:
        value = data.get(field)
        if value is None or not str(value).strip():
            missing.append(field)
    if missing:
        raise ApiError(f"Missing required fields: {', '.join(missing)}")


def clean(data, key, max_len=None):
    """Return data[key] as a stripped string ('' if missing); enforce max length."""
    value = data.get(key)
    value = "" if value is None else str(value).strip()
    if max_len and len(value) > max_len:
        raise ApiError(f"{key} must be at most {max_len} characters")
    return value


def clean_email(data, key="email"):
    email = clean(data, key, 150).lower()
    if not EMAIL_RE.match(email):
        raise ApiError("Enter a valid email address.")
    return email


def email_from_query():
    email = request.args.get("email", "").strip().lower()
    if not email:
        raise ApiError("Email is required")
    return email


def parse_int(value, field):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(f"{field} must be a whole number")


def parse_quantity(value, field="quantity"):
    quantity = parse_int(value, field)
    if quantity < 1 or quantity > MAX_QUANTITY:
        raise ApiError(f"{field} must be between 1 and {MAX_QUANTITY}")
    return quantity


def parse_amount(value, field="amount"):
    try:
        number = round(float(value), 2)
    except (TypeError, ValueError):
        raise ApiError(f"{field} must be a number")
    if not math.isfinite(number) or number <= 0 or number > MAX_AMOUNT:
        raise ApiError(f"{field} must be greater than 0 and at most {MAX_AMOUNT:,}")
    return number


def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    return None


# ----------------------------------------------------------------------------
# Auth tokens
# ----------------------------------------------------------------------------
def issue_token(user):
    if not serializer:
        return None
    return serializer.dumps({"uid": user["id"], "email": user["email"]})


def authorize(email):
    """When AUTH_REQUIRED=true, the caller's token must belong to `email`."""
    if not AUTH_REQUIRED:
        return
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    try:
        payload = serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except BadSignature:
        raise ApiError("Unauthorized", 401)
    if payload.get("email") != email:
        raise ApiError("Forbidden", 403)


# ----------------------------------------------------------------------------
# OTP helpers
# ----------------------------------------------------------------------------
def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


def otp_matches(stored, provided):
    if not stored:
        return False
    return hmac.compare_digest(str(stored).encode("utf-8"), provided.encode("utf-8"))


def otp_sent_recently(expiry, ttl_minutes):
    if not expiry:
        return False
    issued_at = expiry - timedelta(minutes=ttl_minutes)
    return (now() - issued_at).total_seconds() < OTP_RESEND_SECONDS


def too_soon_response():
    return jsonify({"error": f"Please wait {OTP_RESEND_SECONDS} seconds before requesting another OTP."}), 429


def too_many_attempts_response():
    return jsonify({"error": "Too many wrong attempts. Please request a new OTP."}), 429


# ----------------------------------------------------------------------------
# Email
# ----------------------------------------------------------------------------
def send_email(subject, recipient, body, html=None):
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        raise RuntimeError("MAIL_USERNAME and MAIL_PASSWORD are required to send email.")
    msg = Message(subject, sender=app.config["MAIL_USERNAME"], recipients=[recipient])
    msg.body = body
    if html:
        msg.html = html
    mail.send(msg)


def send_otp_email(subject, recipient, body):
    try:
        send_email(subject, recipient, body)
    except Exception:
        app.logger.exception("Could not send OTP email")
        raise ApiError("Could not send the OTP email. Please try again.", 502)


def send_email_in_background(subject, recipient, body, html):
    def worker():
        try:
            with app.app_context():
                send_email(subject, recipient, body, html)
        except Exception:
            app.logger.exception("Background email failed (%s)", subject)

    threading.Thread(target=worker, daemon=True).start()


def mail_is_configured():
    return bool(app.config["MAIL_USERNAME"] and app.config["MAIL_PASSWORD"])


CELL = "padding:8px;border-bottom:1px solid #e5e7eb;"
BOX = "border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin:16px 0;"


def e(value):
    return escape(str(value))


def money(value):
    return f"Rs. {float(value):.2f}"


def build_order_receipt(order):
    items = order.get("items") or []
    total_quantity = sum(int(item.get("quantity") or 0) for item in items)
    payment_method = order.get("payment_method") or "Not provided"
    payment_status = order.get("payment_status") or "Not provided"
    transaction_reference = order.get("transaction_reference") or "Not provided"
    payment_notes = order.get("payment_notes") or "Not provided"
    shipping_phone = order.get("shipping_phone") or "Not provided"
    shipping_address = order.get("shipping_address") or "Not provided"

    item_lines = "\n".join(
        f"{index}. Product ID: {item.get('product_id') or 'Not provided'}\n"
        f"   Name: {item.get('product_name') or 'Product'}\n"
        f"   Image: {item.get('product_image') or 'Not provided'}\n"
        f"   Quantity: {int(item.get('quantity') or 0)}\n"
        f"   Unit Price: {money(item.get('price') or 0)}\n"
        f"   Subtotal: {money(item.get('subtotal') or 0)}"
        for index, item in enumerate(items, start=1)
    ) or "No item details found."

    text_body = (
        f"Hello {order['shipping_name']},\n\n"
        f"Your Google Store order in {SITE_NAME} #{order['id']} has been placed successfully.\n\n"
        "Customer Details\n----------------\n"
        f"Name: {order['shipping_name']}\n"
        f"Email: {order['shipping_email']}\n"
        f"Phone: {shipping_phone}\n\n"
        "Shipping Details\n----------------\n"
        f"Address:\n{shipping_address}\n\n"
        "Order Details\n-------------\n"
        f"Order ID: {order['id']}\n"
        f"Order Date: {order['created_at']}\n"
        f"Order Status: {order['status']}\n\n"
        "Payment Details\n---------------\n"
        f"Payment Method: {payment_method}\n"
        f"Payment Status: {payment_status}\n"
        f"Transaction Reference: {transaction_reference}\n"
        f"Payment Notes: {payment_notes}\n\n"
        "Products Purchased\n------------------\n"
        f"{item_lines}\n\n"
        "Amount Summary\n--------------\n"
        f"Total Quantity: {total_quantity}\n"
        f"Total Paid: {money(order['total_amount'])}\n\n"
        "Thank you for shopping with Google Store."
    )

    rows = "".join(
        "<tr>"
        f"<td style='{CELL}'>{e(item.get('product_id') or '')}</td>"
        f"<td style='{CELL}'><strong>{e(item.get('product_name') or 'Product')}</strong><br>"
        f"<span style='color:#64748b;font-size:12px;word-break:break-all;'>{e(item.get('product_image') or 'No image saved')}</span></td>"
        f"<td style='{CELL}text-align:center;'>{int(item.get('quantity') or 0)}</td>"
        f"<td style='{CELL}text-align:right;'>{money(item.get('price') or 0)}</td>"
        f"<td style='{CELL}text-align:right;'>{money(item.get('subtotal') or 0)}</td>"
        "</tr>"
        for item in items
    ) or f"<tr><td colspan='5' style='{CELL}'>No item details found.</td></tr>"

    address_html = e(shipping_address).replace("\n", "<br>")
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:760px;margin:0 auto;padding:24px;color:#202124;">
      <h2 style="margin-top:0;color:#1a73e8;">multicloud devops veera sir store Receipt</h2>
      <p>Your order <strong>#{e(order['id'])}</strong> has been placed successfully.</p>
      <div style="{BOX}background:#f8fafc;">
        <h3 style="margin:0 0 8px;color:#0f172a;">Customer Details</h3>
        <strong>Name:</strong> {e(order['shipping_name'])}<br>
        <strong>Email:</strong> {e(order['shipping_email'])}<br>
        <strong>Phone:</strong> {e(shipping_phone)}
      </div>
      <div style="{BOX}">
        <h3 style="margin:0 0 8px;color:#0f172a;">Shipping Details</h3>
        <strong>Address:</strong><br>{address_html}
      </div>
      <div style="{BOX}background:#f8fafc;">
        <h3 style="margin:0 0 8px;color:#0f172a;">Order &amp; Payment Details</h3>
        <strong>Order ID:</strong> #{e(order['id'])}<br>
        <strong>Order Date:</strong> {e(order['created_at'])}<br>
        <strong>Order Status:</strong> {e(order['status'])}<br>
        <strong>Payment Method:</strong> {e(payment_method)}<br>
        <strong>Payment Status:</strong> {e(payment_status)}<br>
        <strong>Transaction Reference:</strong> {e(transaction_reference)}<br>
        <strong>Payment Notes:</strong> {e(payment_notes)}
      </div>
      <table style="width:100%;border-collapse:collapse;margin:20px 0;">
        <thead>
          <tr style="background:#f8f9fa;">
            <th style="{CELL}text-align:left;">Product ID</th>
            <th style="{CELL}text-align:left;">Product</th>
            <th style="{CELL}text-align:center;">Qty</th>
            <th style="{CELL}text-align:right;">Price</th>
            <th style="{CELL}text-align:right;">Subtotal</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <div style="text-align:right;border-top:2px solid #e5e7eb;padding-top:12px;">
        <strong>Total Quantity:</strong> {total_quantity}<br>
        <strong>Total Paid:</strong> {money(order['total_amount'])}
      </div>
      <p style="margin-top:24px;">Thank you for shopping with Google Store.</p>
    </div>
    """
    return text_body, html_body


def build_recharge_receipt(recharge):
    details = [
        ("Email", recharge["email"]),
        ("Mobile Number", recharge["mobile_number"]),
        ("Operator", recharge["operator_name"]),
        ("Plan", recharge["plan_name"] or "Custom plan"),
        ("Amount Paid", money(recharge["amount"])),
        ("Payment Method", recharge["payment_method"]),
        ("Status", recharge["status"]),
        ("Transaction Reference", recharge["transaction_reference"] or "Not provided"),
        ("Date", recharge["created_at"]),
    ]
    text_body = (
        f"Hello {recharge['email']},\n\n"
        f"Your Google Pay recharge in {SITE_NAME} #{recharge['id']} has been saved successfully.\n\n"
        "Recharge Details\n----------------\n"
        + "\n".join(f"{label}: {value}" for label, value in details[1:])
        + "\n\nThank you for using Google Pay."
    )
    rows = "".join(
        f"<tr><td style='{CELL}'><strong>{e(label)}</strong></td><td style='{CELL}'>{e(value)}</td></tr>"
        for label, value in details
    )
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;padding:24px;color:#202124;">
      <h2 style="margin-top:0;color:#1a73e8;">Google Pay Recharge Receipt</h2>
      <p>Your recharge <strong>#{e(recharge['id'])}</strong> has been saved successfully.</p>
      <table style="width:100%;border-collapse:collapse;margin:20px 0;"><tbody>{rows}</tbody></table>
      <p>Thank you for using Google Pay.</p>
    </div>
    """
    return text_body, html_body


# ----------------------------------------------------------------------------
# Data access and serializers
# ----------------------------------------------------------------------------
def iso(value):
    return value.isoformat() if value else None


def public_user(user):
    return {key: user[key] for key in ("id", "username", "full_name", "email", "address", "phone")}


def fetch_user_by_email(cursor, email):
    cursor.execute(
        """
        SELECT id, username, full_name, email, address, phone, otp_code, otp_expiry,
               otp_attempts, last_login_otp_verified_at
        FROM users
        WHERE email = %s
        """,
        (email,),
    )
    return cursor.fetchone()


def require_user(cursor, email):
    user = fetch_user_by_email(cursor, email)
    if not user:
        raise ApiError("User not found", 404)
    return user


def should_require_daily_login_otp(user):
    last_verified = user.get("last_login_otp_verified_at")
    if not last_verified:
        return True
    return last_verified.date() != now().date()


def serialize_cart_row(row):
    return {
        "id": row["id"],
        "product_id": row["product_id"],
        "product_name": row["product_name"],
        "product_image": row["product_image"],
        "product_description": row["product_description"],
        "price": float(row["price"]),
        "quantity": row["quantity"],
        "subtotal": round(float(row["price"]) * row["quantity"], 2),
        "updated_at": iso(row["updated_at"]),
    }


def fetch_cart(cursor, user_id):
    cursor.execute(
        """
        SELECT id, product_id, product_name, product_image, product_description,
               price, quantity, updated_at
        FROM cart_items
        WHERE user_id = %s
        ORDER BY updated_at DESC, id DESC
        """,
        (user_id,),
    )
    items = [serialize_cart_row(row) for row in cursor.fetchall()]
    total = round(sum(item["subtotal"] for item in items), 2)
    return {"items": items, "total": total}


def serialize_order_item(item):
    return {
        "product_id": item["product_id"],
        "product_name": item["product_name"],
        "product_image": item["product_image"],
        "price": float(item["price"]),
        "quantity": item["quantity"],
        "subtotal": round(float(item["price"]) * item["quantity"], 2),
    }


def normalize_order_item(item):
    """Clean an item sent by the browser. Subtotal is always computed here."""
    price = parse_amount(item.get("price"), "item price")
    quantity = parse_quantity(item.get("quantity") or 1, "item quantity")
    fields = {
        "product_id": item.get("product_id") or item.get("id") or "product",
        "product_name": item.get("product_name") or item.get("name") or "Product",
        "product_image": item.get("product_image") or item.get("image"),
    }
    return {
        "product_id": clean(fields, "product_id", 100),
        "product_name": clean(fields, "product_name", 255),
        "product_image": clean(fields, "product_image") or None,
        "price": price,
        "quantity": quantity,
        "subtotal": round(price * quantity, 2),
    }


def fetch_orders(cursor, user_id):
    cursor.execute(
        """
        SELECT id, shipping_name, shipping_email, shipping_address, shipping_phone,
               total_amount, status, created_at
        FROM orders
        WHERE user_id = %s
        ORDER BY created_at DESC, id DESC
        """,
        (user_id,),
    )
    orders = cursor.fetchall()
    items_by_order = {}
    if orders:
        order_ids = [order["id"] for order in orders]
        placeholders = ",".join(["%s"] * len(order_ids))
        cursor.execute(
            f"""
            SELECT order_id, product_id, product_name, product_image, price, quantity
            FROM order_items
            WHERE order_id IN ({placeholders})
            ORDER BY id ASC
            """,
            order_ids,
        )
        for row in cursor.fetchall():
            items_by_order.setdefault(row["order_id"], []).append(serialize_order_item(row))
    for order in orders:
        order["items"] = items_by_order.get(order["id"], [])
        order["total_amount"] = float(order["total_amount"])
        order["created_at"] = iso(order["created_at"])
    return orders


def fetch_payments(cursor, user_id):
    cursor.execute(
        """
        SELECT id, order_id, payment_type, payment_method, amount, status,
               transaction_reference, notes, created_at
        FROM payments
        WHERE user_id = %s
        ORDER BY created_at DESC, id DESC
        """,
        (user_id,),
    )
    return [
        {
            "id": row["id"],
            "order_id": row["order_id"],
            "payment_type": row["payment_type"],
            "payment_method": row["payment_method"],
            "amount": float(row["amount"]),
            "status": row["status"],
            "transaction_reference": row["transaction_reference"],
            "notes": row["notes"],
            "created_at": iso(row["created_at"]),
        }
        for row in cursor.fetchall()
    ]


def fetch_recharges(cursor, user_id):
    cursor.execute(
        """
        SELECT id, mobile_number, operator_name, plan_name, amount, payment_method,
               status, transaction_reference, created_at
        FROM recharges
        WHERE user_id = %s
        ORDER BY created_at DESC, id DESC
        """,
        (user_id,),
    )
    return [
        {
            "id": row["id"],
            "mobile_number": row["mobile_number"],
            "operator_name": row["operator_name"],
            "plan_name": row["plan_name"],
            "amount": float(row["amount"]),
            "payment_method": row["payment_method"],
            "status": row["status"],
            "transaction_reference": row["transaction_reference"],
            "created_at": iso(row["created_at"]),
        }
        for row in cursor.fetchall()
    ]


def fetch_service_activity(cursor, user_id):
    cursor.execute(
        """
        SELECT id, service_name, service_path, activity_type, note, created_at
        FROM service_activity
        WHERE user_id = %s
        ORDER BY created_at DESC, id DESC
        """,
        (user_id,),
    )
    return [
        {
            "id": row["id"],
            "service_name": row["service_name"],
            "service_path": row["service_path"],
            "activity_type": row["activity_type"],
            "note": row["note"],
            "created_at": iso(row["created_at"]),
        }
        for row in cursor.fetchall()
    ]


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------
@app.route("/api", methods=["GET"], strict_slashes=False)
def api_root():
    return jsonify(
        {
            "message": "API is running successfully",
            "status": "healthy",
            "service": "Google Store Backend",
            "timestamp": now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    ), 200


# ----------------------------------------------------------------------------
# Signup / login
# ----------------------------------------------------------------------------
@app.route("/api/signup/request", methods=["POST"], strict_slashes=False)
def signup_request():
    data = get_json_payload()
    require_fields(data, ["username", "email", "password"])

    email = clean_email(data)
    username = clean(data, "username", 100)
    full_name = clean(data, "full_name", 150) or username
    password = clean(data, "password")
    password_error = validate_password_strength(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    password_hash = generate_password_hash(password)
    otp = generate_otp()
    expiry = now() + timedelta(minutes=SIGNUP_OTP_MINUTES)

    with db_session() as (conn, cursor):
        cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 409

        cursor.execute("SELECT otp_expiry FROM pending_signups WHERE email = %s", (email,))
        pending = cursor.fetchone()
        if pending and otp_sent_recently(pending["otp_expiry"], SIGNUP_OTP_MINUTES):
            return too_soon_response()

        cursor.execute(
            """
            INSERT INTO pending_signups
                (email, username, full_name, password_hash, otp_code, otp_expiry, otp_attempts)
            VALUES (%s, %s, %s, %s, %s, %s, 0)
            ON DUPLICATE KEY UPDATE
                username = VALUES(username),
                full_name = VALUES(full_name),
                password_hash = VALUES(password_hash),
                otp_code = VALUES(otp_code),
                otp_expiry = VALUES(otp_expiry),
                otp_attempts = 0
            """,
            (email, username, full_name, password_hash, otp, expiry),
        )
        conn.commit()

    send_otp_email(
        "Google Store - Verify Registration",
        email,
        f"Hello {username}, your registration OTP for {SITE_NAME} is {otp}. "
        f"It expires in {SIGNUP_OTP_MINUTES} minutes.",
    )
    return jsonify({"message": "OTP sent to email!"}), 200


@app.route("/api/signup/verify", methods=["POST"], strict_slashes=False)
def signup_verify():
    data = get_json_payload()
    require_fields(data, ["email", "otp"])
    email = clean(data, "email", 150).lower()
    user_otp = clean(data, "otp", 10)

    with db_session() as (conn, cursor):
        cursor.execute("SELECT * FROM pending_signups WHERE email = %s", (email,))
        pending = cursor.fetchone()
        if not pending:
            return jsonify({"error": "Signup request not found"}), 404
        if pending["otp_attempts"] >= OTP_MAX_ATTEMPTS:
            return too_many_attempts_response()
        if now() >= pending["otp_expiry"]:
            return jsonify({"error": "Invalid or expired OTP"}), 401
        if not otp_matches(pending["otp_code"], user_otp):
            cursor.execute(
                "UPDATE pending_signups SET otp_attempts = otp_attempts + 1 WHERE email = %s",
                (email,),
            )
            conn.commit()
            return jsonify({"error": "Invalid or expired OTP"}), 401

        try:
            cursor.execute(
                "INSERT INTO users (username, full_name, email, password) VALUES (%s, %s, %s, %s)",
                (pending["username"], pending["full_name"], pending["email"], pending["password_hash"]),
            )
            cursor.execute("DELETE FROM pending_signups WHERE email = %s", (email,))
            conn.commit()
        except pymysql.err.IntegrityError:
            conn.rollback()
            return jsonify({"error": "User already exists"}), 409

    return (
        jsonify(
            {
                "message": "Account created successfully!",
                "user": {
                    "username": pending["username"],
                    "full_name": pending["full_name"],
                    "email": pending["email"],
                },
            }
        ),
        201,
    )


@app.route("/api/login/request", methods=["POST"], strict_slashes=False)
def login_request():
    data = get_json_payload()
    require_fields(data, ["email", "password"])
    email = clean(data, "email", 150).lower()
    password = clean(data, "password")

    with db_session() as (conn, cursor):
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        if not should_require_daily_login_otp(user):
            cursor.execute(
                "UPDATE users SET otp_code = NULL, otp_expiry = NULL, otp_attempts = 0 WHERE id = %s",
                (user["id"],),
            )
            conn.commit()
            return (
                jsonify(
                    {
                        "message": "Login successful",
                        "otp_required": False,
                        "user": public_user(user),
                        "token": issue_token(user),
                    }
                ),
                200,
            )

        if otp_sent_recently(user["otp_expiry"], LOGIN_OTP_MINUTES):
            return too_soon_response()

        otp = generate_otp()
        expiry = now() + timedelta(minutes=LOGIN_OTP_MINUTES)
        cursor.execute(
            "UPDATE users SET otp_code = %s, otp_expiry = %s, otp_attempts = 0 WHERE id = %s",
            (otp, expiry, user["id"]),
        )
        conn.commit()

    send_otp_email(
        "Google Store - Login OTP",
        email,
        f"Your login OTP for {SITE_NAME} is {otp}. It expires in {LOGIN_OTP_MINUTES} minutes.",
    )
    return jsonify({"message": "OTP sent to email", "otp_required": True}), 200


@app.route("/api/login/verify", methods=["POST"], strict_slashes=False)
def login_verify():
    data = get_json_payload()
    require_fields(data, ["email", "otp"])
    email = clean(data, "email", 150).lower()
    user_otp = clean(data, "otp", 10)

    with db_session() as (conn, cursor):
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user or not user["otp_code"] or not user["otp_expiry"]:
            return jsonify({"error": "Invalid or expired OTP"}), 401
        if user["otp_attempts"] >= OTP_MAX_ATTEMPTS:
            return too_many_attempts_response()
        if now() >= user["otp_expiry"]:
            return jsonify({"error": "Invalid or expired OTP"}), 401
        if not otp_matches(user["otp_code"], user_otp):
            cursor.execute("UPDATE users SET otp_attempts = otp_attempts + 1 WHERE id = %s", (user["id"],))
            conn.commit()
            return jsonify({"error": "Invalid or expired OTP"}), 401

        cursor.execute(
            """
            UPDATE users
            SET otp_code = NULL, otp_expiry = NULL, otp_attempts = 0,
                last_login_otp_verified_at = %s
            WHERE id = %s
            """,
            (now(), user["id"]),
        )
        conn.commit()

    return (
        jsonify({"message": "Login successful", "user": public_user(user), "token": issue_token(user)}),
        200,
    )


# ----------------------------------------------------------------------------
# Profile
# ----------------------------------------------------------------------------
@app.route("/api/users/<path:email>", methods=["GET"])
def get_user_profile(email):
    email = email.strip().lower()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify({"user": public_user(user)}), 200


@app.route("/api/users/<path:email>", methods=["PUT"])
def update_user_profile(email):
    email = email.strip().lower()
    authorize(email)
    data = get_json_payload()
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        full_name = clean(data, "full_name", 150) if "full_name" in data else user["full_name"]
        address = (clean(data, "address", 1000) or None) if "address" in data else user["address"]
        phone = (clean(data, "phone", 20) or None) if "phone" in data else user["phone"]
        cursor.execute(
            "UPDATE users SET full_name = %s, address = %s, phone = %s WHERE id = %s",
            (full_name or user["username"], address, phone, user["id"]),
        )
        conn.commit()
        return jsonify({"message": "Profile updated successfully"}), 200


# ----------------------------------------------------------------------------
# Cart
# ----------------------------------------------------------------------------
@app.route("/api/cart", methods=["GET"], strict_slashes=False)
def get_cart():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify(fetch_cart(cursor, user["id"])), 200


@app.route("/api/cart/items", methods=["POST"], strict_slashes=False)
def add_cart_item():
    data = get_json_payload()
    require_fields(data, ["email", "product_id", "product_name", "price"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    quantity = parse_quantity(data.get("quantity", 1))
    product_id = clean(data, "product_id", 100)
    product_name = clean(data, "product_name", 255)
    product_image = clean(data, "product_image") or None
    product_description = clean(data, "product_description") or None
    price = parse_amount(data["price"], "price")

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        cursor.execute(
            """
            INSERT INTO cart_items
                (user_id, product_id, product_name, product_image, product_description, price, quantity)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                product_name = VALUES(product_name),
                product_image = VALUES(product_image),
                product_description = VALUES(product_description),
                price = VALUES(price),
                quantity = LEAST(quantity + VALUES(quantity), %s)
            """,
            (user["id"], product_id, product_name, product_image, product_description, price, quantity, MAX_QUANTITY),
        )
        conn.commit()
        return jsonify({"message": "Item added to cart"}), 201


@app.route("/api/cart/items", methods=["PUT"], strict_slashes=False)
def update_cart_item():
    data = get_json_payload()
    require_fields(data, ["email", "product_id", "quantity"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    product_id = clean(data, "product_id", 100)
    quantity = parse_int(data["quantity"], "quantity")
    if quantity > MAX_QUANTITY:
        raise ApiError(f"quantity must be at most {MAX_QUANTITY}")

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        if quantity <= 0:
            cursor.execute(
                "DELETE FROM cart_items WHERE user_id = %s AND product_id = %s",
                (user["id"], product_id),
            )
        else:
            cursor.execute(
                "UPDATE cart_items SET quantity = %s WHERE user_id = %s AND product_id = %s",
                (quantity, user["id"], product_id),
            )
        conn.commit()
        return jsonify({"message": "Cart updated"}), 200


@app.route("/api/cart/items", methods=["DELETE"], strict_slashes=False)
def delete_cart_item():
    data = get_json_payload()
    email = clean(data, "email", 150).lower()
    product_id = clean(data, "product_id", 100)
    if not email or not product_id:
        raise ApiError("Email and product_id are required")
    authorize(email)

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        cursor.execute(
            "DELETE FROM cart_items WHERE user_id = %s AND product_id = %s",
            (user["id"], product_id),
        )
        conn.commit()
        return jsonify({"message": "Item removed from cart"}), 200


# ----------------------------------------------------------------------------
# Orders
# ----------------------------------------------------------------------------
@app.route("/api/orders", methods=["POST"], strict_slashes=False)
def create_order():
    data = get_json_payload()
    require_fields(data, ["email", "shipping_name", "shipping_address"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    shipping_name = clean(data, "shipping_name", 150)
    shipping_address = clean(data, "shipping_address", 1000)
    shipping_phone = clean(data, "shipping_phone", 20) or None
    status = "placed"  # decided by the server, not the browser
    payment_method = clean(data, "payment_method", 50) or None
    payment_status = clean(data, "payment_status", 50) or "paid"
    transaction_reference = clean(data, "transaction_reference", 150) or None
    payment_notes = clean(data, "payment_notes") or None
    request_items = [
        normalize_order_item(item) for item in (data.get("items") or []) if isinstance(item, dict)
    ]

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        cart = fetch_cart(cursor, user["id"])
        order_items = cart["items"] or request_items
        if not order_items:
            raise ApiError("Cart is empty")
        order_total = round(sum(item["price"] * item["quantity"] for item in order_items), 2)

        cursor.execute(
            """
            INSERT INTO orders
                (user_id, shipping_name, shipping_email, shipping_address, shipping_phone, total_amount, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (user["id"], shipping_name, email, shipping_address, shipping_phone, order_total, status),
        )
        order_id = cursor.lastrowid

        cursor.executemany(
            """
            INSERT INTO order_items (order_id, product_id, product_name, product_image, price, quantity)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            [
                (order_id, i["product_id"], i["product_name"], i["product_image"], i["price"], i["quantity"])
                for i in order_items
            ],
        )

        cursor.execute("DELETE FROM cart_items WHERE user_id = %s", (user["id"],))
        cursor.execute(
            "UPDATE users SET full_name = %s, address = %s, phone = COALESCE(%s, phone) WHERE id = %s",
            (shipping_name, shipping_address, shipping_phone, user["id"]),
        )

        if payment_method:
            cursor.execute(
                """
                INSERT INTO payments
                    (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (user["id"], order_id, "order", payment_method, order_total, payment_status,
                 transaction_reference, payment_notes),
            )
        conn.commit()

    order_payload = {
        "id": order_id,
        "shipping_name": shipping_name,
        "shipping_email": email,
        "shipping_address": shipping_address,
        "shipping_phone": shipping_phone,
        "total_amount": order_total,
        "status": status,
        "payment_method": payment_method,
        "payment_status": payment_status,
        "transaction_reference": transaction_reference,
        "payment_notes": payment_notes,
        "created_at": now().strftime("%Y-%m-%d %H:%M:%S"),
        "items": [serialize_order_item(item) for item in order_items],
    }

    email_queued = mail_is_configured()
    if email_queued:
        text_body, html_body = build_order_receipt(order_payload)
        send_email_in_background(
            f"multicloud devops veera sir store - Order #{order_id}", email, text_body, html_body
        )
        email_message = "Receipt email is being sent in the background."
    else:
        email_message = "Receipt email was not sent because MAIL_USERNAME or MAIL_PASSWORD is missing."

    return (
        jsonify(
            {
                "message": "Order placed successfully",
                "order_id": order_id,
                "total_amount": order_total,
                "email_queued": email_queued,
                "email_message": email_message,
                "order": order_payload,
            }
        ),
        201,
    )


@app.route("/api/orders", methods=["GET"], strict_slashes=False)
def get_orders():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify({"orders": fetch_orders(cursor, user["id"])}), 200


# ----------------------------------------------------------------------------
# Payments
# ----------------------------------------------------------------------------
@app.route("/api/payments", methods=["POST"], strict_slashes=False)
def create_payment():
    data = get_json_payload()
    require_fields(data, ["email", "payment_method", "amount"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    payment_type = clean(data, "payment_type", 50) or "payment"
    payment_method = clean(data, "payment_method", 50)
    amount = parse_amount(data["amount"])
    status = clean(data, "status", 50) or "paid"
    transaction_reference = clean(data, "transaction_reference", 150) or None
    notes = clean(data, "notes") or None
    order_id = parse_int(data["order_id"], "order_id") if data.get("order_id") not in (None, "") else None

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        if order_id is not None:
            cursor.execute("SELECT id FROM orders WHERE id = %s AND user_id = %s", (order_id, user["id"]))
            if not cursor.fetchone():
                raise ApiError("Order not found", 404)

        cursor.execute(
            """
            INSERT INTO payments
                (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user["id"], order_id, payment_type, payment_method, amount, status, transaction_reference, notes),
        )
        conn.commit()
        return jsonify({"message": "Payment saved successfully", "payment_id": cursor.lastrowid}), 201


@app.route("/api/payments", methods=["GET"], strict_slashes=False)
def get_payments():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify({"payments": fetch_payments(cursor, user["id"])}), 200


# ----------------------------------------------------------------------------
# Recharges
# ----------------------------------------------------------------------------
@app.route("/api/recharges", methods=["POST"], strict_slashes=False)
def create_recharge():
    data = get_json_payload()
    require_fields(data, ["email", "mobile_number", "operator_name", "amount", "payment_method"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    mobile_number = re.sub(r"[\s-]", "", clean(data, "mobile_number", 30))
    if not PHONE_RE.match(mobile_number):
        raise ApiError("Enter a valid mobile number.")
    operator_name = clean(data, "operator_name", 100)
    plan_name = clean(data, "plan_name", 255) or None
    amount = parse_amount(data["amount"])
    payment_method = clean(data, "payment_method", 50)
    status = clean(data, "status", 50) or "success"
    transaction_reference = clean(data, "transaction_reference", 150) or None

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        cursor.execute(
            """
            INSERT INTO recharges
                (user_id, mobile_number, operator_name, plan_name, amount, payment_method, status, transaction_reference)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user["id"], mobile_number, operator_name, plan_name, amount, payment_method, status,
             transaction_reference),
        )
        recharge_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO payments
                (user_id, order_id, payment_type, payment_method, amount, status, transaction_reference, notes)
            VALUES (%s, NULL, %s, %s, %s, %s, %s, %s)
            """,
            (user["id"], "recharge", payment_method, amount, status, transaction_reference,
             f"Recharge for {mobile_number} ({operator_name})"),
        )
        conn.commit()

    recharge_payload = {
        "id": recharge_id,
        "email": email,
        "mobile_number": mobile_number,
        "operator_name": operator_name,
        "plan_name": plan_name,
        "amount": amount,
        "payment_method": payment_method,
        "status": status,
        "transaction_reference": transaction_reference,
        "created_at": now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    email_queued = mail_is_configured()
    if email_queued:
        text_body, html_body = build_recharge_receipt(recharge_payload)
        send_email_in_background(f"Google Pay Recharge Receipt #{recharge_id}", email, text_body, html_body)
        email_message = "Recharge receipt email is being sent in the background."
    else:
        email_message = "Recharge receipt email was not sent because MAIL_USERNAME or MAIL_PASSWORD is missing."

    return (
        jsonify(
            {
                "message": "Recharge saved successfully",
                "recharge_id": recharge_id,
                "email_queued": email_queued,
                "email_message": email_message,
                "recharge": recharge_payload,
            }
        ),
        201,
    )


@app.route("/api/recharges", methods=["GET"], strict_slashes=False)
def get_recharges():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify({"recharges": fetch_recharges(cursor, user["id"])}), 200


# ----------------------------------------------------------------------------
# Service activity and history
# ----------------------------------------------------------------------------
@app.route("/api/service-activity", methods=["POST"], strict_slashes=False)
def create_service_activity():
    data = get_json_payload()
    require_fields(data, ["email", "service_name"])
    email = clean(data, "email", 150).lower()
    authorize(email)

    service_name = clean(data, "service_name", 100)
    service_path = clean(data, "service_path", 255) or None
    activity_type = clean(data, "activity_type", 50) or "open"
    note = clean(data, "note", 255) or None

    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        cursor.execute(
            """
            INSERT INTO service_activity (user_id, service_name, service_path, activity_type, note)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user["id"], service_name, service_path, activity_type, note),
        )
        conn.commit()
        return jsonify({"message": "Service activity saved", "activity_id": cursor.lastrowid}), 201


@app.route("/api/service-activity", methods=["GET"], strict_slashes=False)
def get_service_activity():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return jsonify({"activities": fetch_service_activity(cursor, user["id"])}), 200


@app.route("/api/history", methods=["GET"], strict_slashes=False)
def get_user_history():
    email = email_from_query()
    authorize(email)
    with db_session() as (conn, cursor):
        user = require_user(cursor, email)
        return (
            jsonify(
                {
                    "orders": fetch_orders(cursor, user["id"]),
                    "payments": fetch_payments(cursor, user["id"]),
                    "recharges": fetch_recharges(cursor, user["id"]),
                    "service_activity": fetch_service_activity(cursor, user["id"]),
                }
            ),
            200,
        )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # Never set FLASK_DEBUG=true on a server: it exposes a remote code console.
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
