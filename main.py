import hashlib
import random
import string
from math import log2

import requests
from flask import Flask, render_template_string, request
app = Flask(__name__)

def calculate_entropy(password): # based on password entropy equation
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += len(string.punctuation)
    return round(len(password) * log2(charset), 2) if charset else 0

def password_strength(password):
    score = 0
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1
    if calculate_entropy(password) >= 50: score += 1
    return score

def is_password_leaked(password):
    passwordhash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    passfirst5 = passwordhash[:5]
    passlast5 = passwordhash[5:]

    response = requests.get("https://api.pwnedpasswords.com/range/" + passfirst5)
    if response.status_code != 200: return False
    hashes = (line.split(":") for line in response.text.splitlines())
    return any(h.strip() == passlast5 for h, _ in hashes)

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

@app.route("/", methods = ["GET", "POST"])
def home():
    results = []
    if request.method == "POST":
        password_file = request.files["password_file"]

        if password_file.filename != "":
            passwords = [line.strip().decode("utf-8") for line in password_file.readlines()]
            for password in passwords:
                strength = password_strength(password)
                entropy = calculate_entropy(password)
                leaked = is_password_leaked(password)
                secure = strength >= 5 and not leaked
                suggestion = generate_password() if not secure else ""

                results.append({
                    "password": password,
                    "strength_score": strength,
                    "entropy": entropy,
                    "leaked": "Yes" if leaked else "No",
                    "secure": secure,
                    "suggested_password": suggestion
                })

        single_pw = request.form.get("password")
        if single_pw: # only runs if not empty
            strength = password_strength(single_pw)
            entropy = calculate_entropy(single_pw)
            leaked = is_password_leaked(single_pw)
            secure = strength >= 5 and not leaked
            suggestion = generate_password() if not secure else ""

            results.append({
                "password": single_pw,
                "strength_score": strength,
                "entropy": entropy,
                "leaked": "Yes" if leaked else "No",
                "secure": secure,
                "suggested_password": suggestion
            })


    return render_template_string("""
        <html>
        <head>
          <title>Password Security Checker</title>
          <style>
            body { font-family: Arial; background:#1e1e1e; color:#f0f0f0; text-align:center; }
            .container { background:#2c2c2c; padding:20px; border-radius:10px; display:inline-block; margin-top:50px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #555; padding: 8px; }
            th { background:#4caf50; }
            td { background:#333; }
            .alert { color:#ff6b6b; font-weight:bold; }
          </style>
        </head>
        <body>
        <div class="container">
          <h1>Password Security Checker</h1>
          <form method="post" enctype="multipart/form-data">
            <label>Upload password file:</label><br>
            <input type="file" name="password_file"><br><br>
        
            <label>Or enter a single password:</label><br>
            <input type="password" name="password"><br><br>
        
            <button type="submit">Check Password(s)</button>
          </form>
        
          {% if results %}
          <table>
            <tr>
              <th>Password</th>
              <th>Strength</th>
              <th>Entropy</th>
              <th>Leaked</th>
              <th>Secure</th>
              <th>Suggested Password</th>
            </tr>
            {% for r in results %}
            <tr>
              <td>{{ r.password }}</td>
              <td>{{ r.strength_score }}</td>
              <td>{{ r.entropy }}</td>
              <td>{{ r.leaked }}</td>
              <td>{{ r.secure }}</td>
              <td>{{ r.suggested_password }}</td>
            </tr>
            {% endfor %}
          </table>
          {% endif %}
        </div>
        </body>
        </html>
    """, results = results)

if __name__ == "__main__":
    app.run(debug=True)