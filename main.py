import streamlit as st
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet

# --- Page config & global styles ---
st.set_page_config(page_title="Secure Data App", layout="centered")

st.markdown("""
    <style>
        .main { background-color: #f7f9fc; }
        h1, h2, h3, h4 {
            color: #1f4e79;
        }
        .stButton>button {
            background-color: #1f4e79;
            color: white;
        }
        .stRadio > div {
            flex-direction: row;
        }
    </style>
""", unsafe_allow_html=True)


# --- Utility functions ---
def derive_key(pass_key, salt):
    key = hashlib.pbkdf2_hmac("sha256", pass_key.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(key)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()

def save_user(email, password):
    salt = os.urandom(16)
    hashed = hash_password(password, salt)
    user_data = {
        "email": email,
        "password": hashed,
        "salt": salt.hex()
    }
    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = []

    if any(u["email"] == email for u in users):
        return False

    users.append(user_data)
    with open("login_data.json", "w") as f:
        json.dump(users, f, indent=4)
    return True

def check_login(email, password):
    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        return False

    for user in users:
        if user["email"] == email:
            salt = bytes.fromhex(user["salt"])
            hashed = hash_password(password, salt)
            return hashed == user["password"]
    return False


# --- Pages ---
def register():
    st.title("📝 Create Your Account")
    with st.form("register_form"):
        email = st.text_input("📧 Email")
        password = st.text_input("🔒 Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if len(password) < 8:
                st.error("❌ Password must be at least 8 characters long.")
            elif not email:
                st.error("❌ Please enter an email.")
            elif save_user(email, password):
                st.success("✅ Registration successful! Please go to Login.")
            else:
                st.warning("⚠️ Email already registered.")


def login():
    st.title("🔓 Login to Your Account")
    with st.form("login_form"):
        email = st.text_input("📧 Email")
        password = st.text_input("🔒 Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if len(email) < 8:
                st.error("📛 Invalid email format.")
            elif check_login(email, password):
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.sidebar.success(f"👋 Welcome, {email}")
                st.success("✅ Login successful!")
            else:
                st.error("❌ Invalid email or password.")


def encrypt_decrypt():
    st.title("🔐 Encrypt / Decrypt Your Data")

    choice = st.radio("🔧 Select Operation", ["Encrypt", "Decrypt"], horizontal=True)
    st.write("")  # Spacer

    if choice == "Encrypt":
        text = st.text_area("📝 Data to Encrypt")
        passkey = st.text_input("🔑 Encryption Key", type="password")

        if st.button("🔒 Encrypt and Save"):
            if text and passkey:
                salt = os.urandom(16)
                key = derive_key(passkey, salt)
                fernet = Fernet(key)

                encrypted = fernet.encrypt(text.encode()).decode()

                data = {
                    "text_data": encrypted,
                    "salt": salt.hex(),
                    "user": st.session_state.user_email
                }

                try:
                    with open("user_data.json", "r") as f:
                        entries = json.load(f)
                except FileNotFoundError:
                    entries = []

                entries.append(data)
                with open("user_data.json", "w") as f:
                    json.dump(entries, f, indent=4)

                st.success("✅ Data encrypted and stored securely.")
            else:
                st.warning("⚠️ Please enter both data and a key.")

    elif choice == "Decrypt":
        try:
            with open("user_data.json", "r") as f:
                entries = json.load(f)
        except FileNotFoundError:
            st.warning("⚠️ No data found.")
            return

        user_entries = [e for e in entries if e["user"] == st.session_state.user_email]

        if not user_entries:
            st.warning("⚠️ No entries found for your account.")
            return

        options = [f"{i + 1}. {e['text_data'][:30]}..." for i, e in enumerate(user_entries)]
        selected = st.selectbox("📦 Choose Encrypted Entry", options)
        passkey = st.text_input("🔑 Decryption Key", type="password")

        if st.button("🔓 Decrypt"):
            idx = options.index(selected)
            entry = user_entries[idx]
            salt = bytes.fromhex(entry["salt"])
            key = derive_key(passkey, salt)
            fernet = Fernet(key)

            try:
                decrypted = fernet.decrypt(entry["text_data"].encode()).decode()
                st.success(f"🔍 Decrypted: {decrypted}")
            except:
                st.error("❌ Incorrect key or corrupted data.")


def home():
    st.title("🔒 Welcome to Secure Data App")
    st.markdown("Secure your sensitive information with encryption.")

    st.markdown("### 🔧 What You Can Do")
    col1, col2 = st.columns(2)
    with col1:
        st.info("📝 Register for a secure account")
        st.info("🔓 Login to access your data")
    with col2:
        st.success("🔐 Encrypt your sensitive info")
        st.success("🔍 Decrypt only with your key")

    st.markdown("---")
    st.markdown("### 🛡️ Security Tips")
    st.markdown("""
    - Use a strong, unique password.
    - Store your encryption keys safely.
    - No password recovery is available.
    """)

    st.markdown("### 📄 Features")
    st.markdown("""
    - Secure encryption & decryption
    - Local password hashing (PBKDF2)
    - Session-based access
    - User-based data separation
    """)


# --- App navigation ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

st.sidebar.title("🔐 Secure Data App")
menu = ["🏠 Home", "📝 Register", "🔓 Login"]
if st.session_state.logged_in:
    menu += ["🔐 Encrypt/Decrypt", "🚪 Logout"]

choice = st.sidebar.radio("Go to:", menu)

if choice == "🏠 Home":
    home()
elif choice == "📝 Register":
    register()
elif choice == "🔓 Login":
    login()
elif choice == "🔐 Encrypt/Decrypt":
    if st.session_state.logged_in:
        encrypt_decrypt()
    else:
        st.error("❗ Please login to access encryption tools.")
elif choice == "🚪 Logout":
    st.session_state.logged_in = False
    st.session_state.user_email = ""
    st.success("🔒 Logged out successfully!")
