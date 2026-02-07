import hashlib
import tkinter as tk
from tkinter import *
from PIL import Image, ImageTk
import math
import string
import os

COMMON_PASSWORD = ["password", "123456", "123456789", "qwerty", "abc123"]

# ---------------- CONFIG ----------------
USER_FILE = "users.txt"
MAX_ATTEMPTS = 3

# ---------------- HASHING ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- FILE HANDLING ----------------
def get_users():
    users = {}
    try:
        with open(USER_FILE, "r") as f:
            for line in f:
                username, pwd_hash, attempts, locked = line.strip().split("|")
                users[username] = {
                    "password": pwd_hash,
                    "attempts": int(attempts),
                    "locked": locked.lower()
                }
    except FileNotFoundError:
        pass
    return users

def save_users(users):
    with open(USER_FILE, "w") as f:
        for u, data in users.items():
            f.write(f"{u}|{data['password']}|{data['attempts']}|{data['locked']}\n")

# ---------------- WINDOW ----------------
root = tk.Tk()
root.geometry("700x400")
root.resizable(False, False)
root.title("Secure Login System")
root.configure(bg="#2B2B2B")

# ---------------- FRAMES ----------------
login_frame = Frame(root, bg="#2B2B2B", width=700, height=400)
signup_frame = Frame(root, bg="#2B2B2B", width=700, height=400)

login_frame.place(x=0, y=0)
signup_frame.place(x=0, y=0)

def show_login():
    signup_frame.place_forget()
    login_frame.place(x=0, y=0)

def show_signup():
    login_frame.place_forget()
    signup_frame.place(x=0, y=0)

# ---------------- IMAGE ----------------
image = Image.open("login.jpg").resize((250, 250))
photo = ImageTk.PhotoImage(image)

Label(login_frame, image=photo, bg="#2B2B2B").place(x=400, y=80)
Label(signup_frame, image=photo, bg="#2B2B2B").place(x=400, y=80)

# ---------------- LOGIN UI ----------------
Label(login_frame, text="Login", font=("Calibri", 25, "bold"),
      bg="#2B2B2B", fg="white").place(x=50, y=30)

Label(login_frame, text="Username", font=("Calibri", 16),
      bg="#2B2B2B", fg="white").place(x=50, y=90)

user_entry = Entry(login_frame, width=30)
user_entry.place(x=50, y=130)

Label(login_frame, text="Password", font=("Calibri", 16),
      bg="#2B2B2B", fg="white").place(x=50, y=160)

pass_entry = Entry(login_frame, width=30, show="*")
pass_entry.place(x=50, y=200)

check_pass = BooleanVar()
def toggle():
    pass_entry.config(show="" if check_pass.get() else "*")

Checkbutton(login_frame, text="Show Password", variable=check_pass,
            bg="#2B2B2B", fg="white", command=toggle).place(x=50, y=230)

result_label = Label(login_frame, text="", bg="#2B2B2B", fg="red")
result_label.place(x=50, y=310)

def logbut():
    username = user_entry.get().strip()
    password = pass_entry.get().strip()

    if not username or not password:
        result_label.config(text="All fields required", font=("Calibri", 12,"bold"))
        return

    users = get_users()

    if username not in users:
        result_label.config(text="User not found")
        return

    user = users[username]

    if user["locked"] == "yes":
        result_label.config(text="Account locked")
        return

    if hash_password(password) == user["password"]:
        user["attempts"] = 0
        result_label.config(text="Login successful!", fg="green")
    else:
        user["attempts"] += 1
        if user["attempts"] >= MAX_ATTEMPTS:
            user["locked"] = "yes"
            result_label.config(text="Account locked after 3 attempts")
        else:
            result_label.config(
                text=f"Wrong password ({MAX_ATTEMPTS - user['attempts']} attempts left)"
            )

    save_users(users)

Button(login_frame, text="Login", width=15, command=logbut).place(x=50, y=270)

Label(login_frame, text="Don't have an account?",
      bg="#2B2B2B", fg="white").place(x=50, y=350)

Button(login_frame, text="Sign Up", bg="#2B2B2B", fg="white",
       relief="flat", command=show_signup).place(x=180, y=347)

# ---------------- SIGNUP UI ----------------
Label(signup_frame, text="Sign Up", font=("Calibri", 25, "bold"),
      bg="#2B2B2B", fg="white").place(x=50, y=30)

Label(signup_frame, text="Username", bg="#2B2B2B",
      fg="white").place(x=50, y=90)

signup_user = Entry(signup_frame, width=30)
signup_user.place(x=50, y=120)

Label(signup_frame, text="Password", bg="#2B2B2B",
      fg="white").place(x=50, y=160)

signup_pass = Entry(signup_frame, width=30, show="*")
signup_pass.place(x=50, y=190)

signup_result = Label(signup_frame, text="", bg="#2B2B2B", fg="green")
signup_result.place(x=50, y=260)
check_pass_signup = BooleanVar()
def toggle_signup():
    signup_pass.config(show="" if check_pass_signup.get() else "*")
Checkbutton(signup_frame, text="Show Password", variable=check_pass_signup,
            bg="#2B2B2B", fg="white", command=toggle_signup).place(x=50, y=220)

# -------- Password strength display (LABELS) ----------
strength_label = Label(signup_frame, text="", bg="#2B2B2B",
                       fg="white", font=("Calibri", 12, "bold"))
strength_label.place(x=50, y=290)

feedback_label = Label(signup_frame, text="", bg="#2B2B2B",
                       fg="#FBBF24", font=("Calibri", 11),
                       justify="left", wraplength=300)
feedback_label.place(x=50, y=320)

def calculate_password_strength(password: str):
    score = 0
    feedback = []
    length = len(password)

    if length == 0:
        return 0, "Invalid", ["Password cannot be empty"]

    if length < 6:
        feedback.append("Password is too short")
    elif 6 <= length <= 7:
        score += 10
    elif 8 <= length <= 9:
        score += 15
    elif 10 <= length <= 12:
        score += 20
    else:
        score += 30

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety < 3:
        feedback.append("Use upper, lower, digits & special characters")

    score += variety * 6.25

    if password.lower() in COMMON_PASSWORD:
        feedback.append("Password is too common")
        score -= 10

    char_set = 0
    if has_lower: char_set += 26
    if has_upper: char_set += 26
    if has_digit: char_set += 10
    if has_special: char_set += len(string.punctuation)

    entropy = length * math.log2(char_set) if char_set else 0
    score += min(entropy / 60 * 20, 20)

    score = max(0, min(100, int(score)))

    if score < 40:
        strength = "Weak"
    elif score < 75:
        strength = "Moderate"
    else:
        strength = "Strong"

    return score, strength, feedback

def password_analyze(password):
    score, strength, feedback = calculate_password_strength(password)

    strength_label.config(text=f"Strength: {strength} ({score}/100)")

    if feedback:
        feedback_label.config(text="• " + "\n• ".join(feedback))
    else:
        feedback_label.config(text="Strong password 👍 No issues found")

    colors = {"Weak": "red", "Moderate": "gold", "Strong": "green"}
    strength_label.config(fg=colors.get(strength, "white"))

Button(signup_frame, text="Analyze Password Strength",
       command=lambda: password_analyze(signup_pass.get())).place(x=50, y=350)

def signup():
    username = signup_user.get().strip()
    password = signup_pass.get().strip()

    if not username or not password:
        signup_result.config(text="All fields required", fg="red")
        return

    users = get_users()

    if username in users:
        signup_result.config(text="User already exists", fg="red")
        return

    users[username] = {
        "password": hash_password(password),
        "attempts": 0,
        "locked": "no"
    }

    save_users(users)
    signup_result.config(text="Signup successful!", fg="green")
    show_login()

Button(signup_frame, text="Create Account",
       width=15, command=signup).place(x=50, y=250)

Button(signup_frame, text="Back to Login",
       width=15, command=show_login).place(x=200, y=250)


'''
pw=input("Enter your password:")
score, strength, feedback=calculate_password_strength(pw)
print(f"Password Strength Score: {score}/100")
print(f"Password Strength Level: {strength}")'''
# ---------------- START ----------------
show_login()
root.mainloop()
