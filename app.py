from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import mysql.connector
from phe import paillier
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# AES key and IV (Initialization Vector)
aes_key = os.urandom(32)
aes_iv = os.urandom(16)

# Paillier keys
paillier_public_key, paillier_private_key = paillier.generate_paillier_keypair()

# Database connection
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'user_db',
    'port': 3309
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# Form classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# Helper functions for encryption and decryption
def encrypt_aes(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted_data):
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()).decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError as e:
        print(f"Padding error during decryption: {e}")
        raise
    return unpadded_data

def encrypt_aes_key(aes_key):
    aes_key_int = int.from_bytes(aes_key, byteorder='big')
    encrypted_key = paillier_public_key.encrypt(aes_key_int)
    return encrypted_key.ciphertext(), encrypted_key.exponent

def decrypt_aes_key(encrypted_key):
    ciphertext, exponent = encrypted_key
    try:
        encrypted_number = paillier.EncryptedNumber(paillier_public_key, int(ciphertext), int(exponent))
    except Exception as e:
        print(f"Error during EncryptedNumber creation: {e}")
        raise

    try:
        decrypted_value = paillier_private_key.decrypt(encrypted_number)
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise

    if decrypted_value < 0:
        decrypted_value = decrypted_value % (1 << 256)  # Modulo with a large power of 2

    decrypted_value_bytes = decrypted_value.to_bytes((decrypted_value.bit_length() + 7) // 8, byteorder='big')

    if len(decrypted_value_bytes) < 32:
        decrypted_value_bytes = decrypted_value_bytes.rjust(32, b'\x00')  # Pad with zeros if too short
    elif len(decrypted_value_bytes) > 32:
        decrypted_value_bytes = decrypted_value_bytes[:32]  # Truncate if too long

    return decrypted_value_bytes

# Hash function (SHA-256 used as a placeholder for MD6)
def hash_password_md6(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = hash_password_md6(password)
        encrypted_password = encrypt_aes(hashed_password.encode())
        encrypted_aes_key = encrypt_aes_key(aes_key)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password, aes_key_ciphertext, aes_key_exponent) VALUES (%s, %s, %s, %s)",
                           (username, encrypted_password, encrypted_aes_key[0], encrypted_aes_key[1]))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash('Username already exists', 'danger')
            print(err)
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = hash_password_md6(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password, aes_key_ciphertext, aes_key_exponent FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        if result:
            stored_encrypted_password, aes_key_ciphertext, aes_key_exponent = result
            
            try:
                stored_aes_key = decrypt_aes_key((aes_key_ciphertext, aes_key_exponent))
                stored_password = decrypt_aes(stored_encrypted_password).decode()
                
                if hashed_password == stored_password:
                    session['username'] = username
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Invalid credentials', 'danger')
            except Exception as e:
                flash(f"An error occurred during login. Please try again.<br>"
                      f"Retrieved encrypted AES key components: ciphertext={aes_key_ciphertext}, exponent={aes_key_exponent}<br>"
                      f"Error during decryption: {e}", 'danger')
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' in session:
        if request.method == 'POST':
            if 'message' in request.form:
                message = request.form['message']
                encrypted_message = encrypt_aes(message.encode())
                return jsonify({'encrypted_message': encrypted_message.hex()})
            elif 'encrypted_message' in request.form:
                encrypted_message_hex = request.form['encrypted_message']
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                try:
                    decrypted_message = decrypt_aes(encrypted_message).decode()
                    return jsonify({'decrypted_message': decrypted_message})
                except Exception as e:
                    return jsonify({'error': str(e)}), 400

        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
