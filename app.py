from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.message import EmailMessage
from threading import Thread
from datetime import datetime, timedelta
import secrets
import os

app = Flask(__name__)
CORS(app, 
    supports_credentials=True,
    resources={
        r"/api/*": {
            "origins": ["https://veera-crt.github.io"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type"],
            "expose_headers": ["Content-Type"],
            "max_age": 86400
        }
    })

# Database connection
DATABASE_URL = os.environ.get("DATABASE_URL")
conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
conn.autocommit = True

def send_otp_email(to_email, otp):
    try:
        msg = EmailMessage()
        msg.set_content(f"Your OTP is: {otp}")
        msg['Subject'] = 'CybVars OTP Verification'
        msg['From'] = "passkey2manager@gmail.com"
        msg['To'] = to_email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login("passkey2manager@gmail.com", "eqkacwkftffzynzc")
            smtp.send_message(msg)
    except Exception as e:
        print(f"Error sending OTP email: {e}")

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        return jsonify(success=False, message="Email already registered"), 409

    otp = f"{random.randint(100000, 999999)}"
    hashed = generate_password_hash(data['password'])

    try:
        cur.execute("""
            INSERT INTO users (full_name, dob, age, email, phone, password_hash, 
                            address, latitude, longitude, otp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data['full_name'], data['dob'], data['age'], email, 
            data['phone'], hashed, data['address'], 
            data['latitude'], data['longitude'], otp
        ))

        Thread(target=send_otp_email, args=(email, otp)).start()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data['email']
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    
    if not user:
        return jsonify(success=False, message="Email not registered"), 404
    
    new_otp = f"{random.randint(100000, 999999)}"
    cur.execute("UPDATE users SET otp = %s WHERE email = %s", (new_otp, email))
    
    Thread(target=send_otp_email, args=(email, new_otp)).start()
    return jsonify(success=True)

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data['email']
    otp_input = data['otp']

    cur = conn.cursor()
    try:
        cur.execute("SELECT otp FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user and user['otp'] == otp_input:
            cur.execute("UPDATE users SET otp_verified = TRUE WHERE email = %s", (email,))
            return jsonify(success=True)

        return jsonify(success=False, message="Invalid OTP"), 400
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, otp_verified FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        return jsonify(success=False, message="Email not registered"), 404

    if not check_password_hash(user['password_hash'], password):
        return jsonify(success=False, message="Incorrect password"), 401

    return jsonify(
        success=True, 
        verified=user['otp_verified'],
        user_id=user['id'],
        email=email
    )

@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify(success=False, message="User ID required"), 400

    cur = conn.cursor()
    cur.execute("""
        SELECT id, website, username, password, notes, created_at 
        FROM passwords 
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user_id,))
    passwords = cur.fetchall()
    return jsonify(success=True, passwords=passwords)

@app.route('/api/passwords', methods=['POST'])
def save_password():
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User ID required'}), 400
        
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')
    notes = data.get('notes')
    
    try:
        cur = conn.cursor()
        cur.execute('INSERT INTO passwords (user_id, website, username, password, notes, created_at) VALUES (%s, %s, %s, %s, %s, NOW())',
                    (user_id, website, username, password, notes))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/passwords/<int:password_id>", methods=["PUT"])
def update_password(password_id):
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify(success=False, message="User ID required"), 400

    website = data.get("website")
    username = data.get("username")
    password = data.get("password")
    notes = data.get("notes")
    otp = data.get("otp")

    cur = conn.cursor()
    cur.execute("SELECT sensitive_action_otp, otp_expires_at FROM users WHERE id = %s", (user_id,))
    result = cur.fetchone()

    if not result or result['sensitive_action_otp'] != otp or result['otp_expires_at'] < datetime.now():
        return jsonify(success=False, message="Invalid or expired OTP"), 400

    try:
        cur.execute("""
            UPDATE passwords 
            SET website = %s, username = %s, password = %s, notes = %s 
            WHERE id = %s AND user_id = %s
        """, (website, username, password, notes, password_id, user_id))
        conn.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route("/api/passwords/<int:password_id>", methods=["GET"])
def get_password_by_id(password_id):
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "User ID required"}), 400

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT website, username, password, notes FROM passwords WHERE id = %s AND user_id = %s",
            (password_id, user_id)
        )
        row = cur.fetchone()

        if not row:
            return jsonify({"success": False, "message": "Password not found"}), 404

        return jsonify({
            "success": True,
            "website": row["website"],
            "username": row["username"],
            "password": row["password"],
            "notes": row["notes"]
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/passwords/<int:password_id>", methods=["DELETE"])
def delete_password(password_id):
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify(success=False, message="User ID required"), 400
    
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM passwords WHERE id = %s AND user_id = %s", 
                   (password_id, user_id))
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route("/")
def home():
    return "🚀 CybVars Flask API is running successfully on Render!"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
