import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64
import pandas as pd
import random
import string
import getpass

# Constants
FILE_NAME = "passwords.csv"
KEY_FILE = "key.key"
SALT = b'\x9a\xd7\xb1\x11\xa7\xd6\x8c\xef\xd6\x99\xcc\x8e\x1a\xba\x9a\x91'

def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

def create_file():
    if not os.path.exists(FILE_NAME):
        df = pd.DataFrame(columns=["Title", "Password", "URL/Application", "Other Information"])
        df.to_csv(FILE_NAME, index=False)

def save_password(title, password, url, info, key):
    create_file()
    encrypted_password = encrypt(password, key)
    df = pd.read_csv(FILE_NAME)
    df = df.append({"Title": title, "Password": encrypted_password, "URL/Application": url, "Other Information": info}, ignore_index=True)
    df.to_csv(FILE_NAME, index=False)

def search_password(title, key):
    create_file()
    df = pd.read_csv(FILE_NAME)
    result = df[df["Title"] == title]
    if result.empty:
        return None
    result["Password"] = result["Password"].apply(lambda x: decrypt(x, key))
    return result

def update_password(title, new_password, key):
    create_file()
    df = pd.read_csv(FILE_NAME)
    encrypted_password = encrypt(new_password, key)
    df.loc[df["Title"] == title, "Password"] = encrypted_password
    df.to_csv(FILE_NAME, index=False)

def delete_password(title):
    create_file()
    df = pd.read_csv(FILE_NAME)
    df = df[df["Title"] != title]
    df.to_csv(FILE_NAME, index=False)

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def on_show_password():
    selected_title = title_entry.get()
    result = search_password(selected_title, user_key)
    if result is not None:
        password = result.iloc[0]["Password"]
        messagebox.showinfo("Decrypted Password", f"The password for {selected_title} is: {password}")
    else:
        messagebox.showerror("Error", "Title not found")

def on_copy_password():
    selected_title = title_entry.get()
    result = search_password(selected_title, user_key)
    if result is not None:
        password = result.iloc[0]["Password"]
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard")
    else:
        messagebox.showerror("Error", "Title not found")

def on_save_password():
    title = title_entry.get()
    password = password_entry.get()
    url = url_entry.get()
    info = info_entry.get()
    save_password(title, password, url, info, user_key)
    messagebox.showinfo("Success", "Password saved successfully")

def on_update_password():
    title = title_entry.get()
    new_password = password_entry.get()
    update_password(title, new_password, user_key)
    messagebox.showinfo("Success", "Password updated successfully")

def on_delete_password():
    title = title_entry.get()
    delete_password(title)
    messagebox.showinfo("Success", "Password deleted successfully")

def on_generate_password():
    generated_password = generate_random_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)

def on_register():
    username = username_entry.get()
    password = password_entry.get()
    key = generate_key(password)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    messagebox.showinfo("Registration Successful", "Registration successful! You can now log in.")
    register_window.destroy()

def on_login():
    global user_key
    username = username_entry.get()
    password = password_entry.get()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            stored_key = f.read()
            entered_key = generate_key(password)
            if stored_key == entered_key:
                user_key = entered_key
                login_window.destroy()
                root.deiconify()
            else:
                messagebox.showerror("Error", "Invalid credentials")
    else:
        messagebox.showerror("Error", "No such user found")

# GUI Setup
root = tk.Tk()
root.title("Password Manager")
root.geometry("400x400")
root.withdraw()

# Login/Register Window
login_window = tk.Toplevel(root)
login_window.title("Login")
login_window.geometry("300x200")

ttk.Label(login_window, text="Username:").grid(column=1, row=1, sticky=tk.W)
username_entry = ttk.Entry(login_window, width=30)
username_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

ttk.Label(login_window, text="Password:").grid(column=1, row=2, sticky=tk.W)
password_entry = ttk.Entry(login_window, width=30, show="*")
password_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

ttk.Button(login_window, text="Login", command=on_login).grid(column=1, row=3, sticky=tk.W)
ttk.Button(login_window, text="Register", command=lambda: register_window.deiconify()).grid(column=2, row=3, sticky=tk.W)

# Register Window
register_window = tk.Toplevel(root)
register_window.title("Register")
register_window.geometry("300x200")
register_window.withdraw()

ttk.Label(register_window, text="Username:").grid(column=1, row=1, sticky=tk.W)
username_entry = ttk.Entry(register_window, width=30)
username_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

ttk.Label(register_window, text="Password:").grid(column=1, row=2, sticky=tk.W)
password_entry = ttk.Entry(register_window, width=30, show="*")
password_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

ttk.Button(register_window, text="Register", command=on_register).grid(column=1, row=3, sticky=tk.W)

# Main Application Window
mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Title, Password, URL/Application, and Other Information input fields
ttk.Label(mainframe, text="Title").grid(column=1, row=1, sticky=tk.W)
title_entry = ttk.Entry(mainframe, width=50)
title_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Password").grid(column=1, row=2, sticky=tk.W)
password_entry = ttk.Entry(mainframe, width=50)
password_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="URL/Application").grid(column=1, row=3, sticky=tk.W)
url_entry = ttk.Entry(mainframe, width=50)
url_entry.grid(column=2, row=3, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Other Information").grid(column=1, row=4, sticky=tk.W)
info_entry = ttk.Entry(mainframe, width=50)
info_entry.grid(column=2, row=4, sticky=(tk.W, tk.E))

# Buttons for Save, Update, Delete, Search, Show Password, Copy Password, Generate Password
ttk.Button(mainframe, text="Save", command=on_save_password).grid(column=1, row=5, sticky=tk.W)
ttk.Button(mainframe, text="Update", command=on_update_password).grid(column=2, row=5, sticky=tk.W)
ttk.Button(mainframe, text="Delete", command=on_delete_password).grid(column=1, row=6, sticky=tk.W)
ttk.Button(mainframe, text="Show Password", command=on_show_password).grid(column=2, row=6, sticky=tk.W)
ttk.Button(mainframe, text="Copy Password", command=on_copy_password).grid(column=1, row=7, sticky=tk.W)
ttk.Button(mainframe, text="Generate Password", command=on_generate_password).grid(column=2, row=7, sticky=tk.W)

root.mainloop()
