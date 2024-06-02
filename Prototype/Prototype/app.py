from flask import Flask, render_template, request, jsonify
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import secrets
import os
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

SENSITIVE_PATTERNS = [
    r'\b\d{16}\b',
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    r'\b\d{1,2}/\d{1,2}/\d{4}\b', 
    r'\b[A-Z]{2}\d{7}\b', 
    r'\b01\d{8,9}\b',
    r'\b\+\d{1,3}\d{9,}\b',
    r'\b\d{10,}\b'
]

AES_KEY = secrets.token_bytes(32)

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'derekliew00@gmail.com'
SENDER_PASSWORD = 'your_password_here'
RECIPIENT_EMAILS = ['hoshaomun0479@gmail.com', 'derekliew0@gmail.com']

def encrypt_data(data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_data_with_iv = iv + encrypted_data
    encrypted_data_b64 = b64encode(encrypted_data_with_iv)
    return encrypted_data_b64.decode('utf-8')

def decrypt_data(encrypted_data_b64):
    encrypted_data_with_iv = b64decode(encrypted_data_b64)
    iv = encrypted_data_with_iv[:AES.block_size]
    encrypted_data = encrypted_data_with_iv[AES.block_size:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/detect', methods=['POST'])
def detect_leak():
    data = request.form['data']
    encrypted_data = encrypt_data(data)
    result = detect_data_leak(data)
    compliance_check = check_compliance(data)
    incident_response = handle_incident_response(result, data)
    response = {
        'result': result,
        'encrypted_data': encrypted_data,
        'compliance_check': compliance_check,
        'incident_response': incident_response
    }
    return jsonify(response)

def detect_data_leak(data):
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, data):
            return "Potential data leak detected!"
    return "No data leak found."

def check_compliance(data):
    compliance_issues = []
    if re.search(r'\bGDPR\s*(?:Article)?\s*\d+\b', data, re.IGNORECASE):
        compliance_issues.append("Potential GDPR violation detected.")
    if re.search(r'\bHIPAA\b', data, re.IGNORECASE):
        compliance_issues.append("Potential HIPAA violation detected.")
    if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', data):
        compliance_issues.append("Potential PCI DSS violation detected.")
    if re.search(r'\bCCPA\b', data, re.IGNORECASE):
        compliance_issues.append("Potential CCPA violation detected.")
    return compliance_issues if compliance_issues else "No compliance issues found."

def handle_incident_response(result, data):
    notifications = []
    if "Potential data leak detected!" in result:
        notifications = send_notification_emails(data)
    return notifications

def send_notification_emails(data):
    notifications = []
    try:
        subject = "Potential Data Leak Detected"
        body = f"A potential data leak has been detected:\n\n{data}"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECIPIENT_EMAILS)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        notifications.append("Notification emails sent successfully.")
    except Exception as e:
        notifications.append(f"Failed to send notification emails: {str(e)}")
    return notifications

@app.route('/decrypt_data', methods=['POST'])
def decrypt():
    encrypted_data = request.form['encrypted_data']
    decrypted_data = decrypt_data(encrypted_data)
    return jsonify({'decrypted_data': decrypted_data})

if __name__ == '__main__':
    app.run(debug=True)