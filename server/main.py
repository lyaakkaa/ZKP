import math
import random
import hashlib

from flask import Flask, request, session, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "supersecretkey"  # В реальности берем из окружения/конфига
CORS(app, supports_credentials=True)  

# -------------------------------
# 1) Глобальные параметры p и g
# -------------------------------
# В реальном проекте это должно быть большое простое p (512, 1024, 2048 бит и т.д.)
# но для демонстрации возьмём маленькое (НЕБЕЗОПАСНО).
p = 467   
g = 2     

# -------------------------------
# 2) "База данных" в памяти
# -------------------------------
# user_db[username] = {
#   "h": g^x mod p
# }
user_db = {}

# challenge_db[username] = e
challenge_db = {}


def hash_password(password: str) -> int:
    """
    Простейший пример превращения пароля в число x.
    В реальности - PBKDF2/Bcrypt/Argon2 и т.д.
    """
    h = hashlib.sha256(password.encode("utf-8")).hexdigest()
    x = int(h, 16)
    # Берём по модулю (p-1), чтобы x < p-1
    x = x % (p - 1)
    if x == 0:
        x = 1
    return x

@app.route("/register", methods=["POST"])
def register():
    """
    Регистрация пользователя:
    - Принимает { "username": "...", "password": "..." }
    - Вычисляет x из пароля
    - Сохраняет h = g^x mod p
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Empty username or password"}), 400
    
    if username in user_db:
        return jsonify({"error": "User already exists"}), 400

    x = hash_password(password)
    h_val = pow(g, x, p)
    user_db[username] = {"h": h_val}

    return jsonify({"message": f"User '{username}' registered", "p": p, "g": g})

@app.route("/login/start", methods=["POST"])
def login_start():
    """
    Начало логина:
    - Принимает { "username": "..." }
    - Генерирует challenge e, сохраняет в challenge_db
    - Возвращает { p, g, h, e }
    """
    data = request.get_json()
    username = data.get("username")

    if username not in user_db:
        return jsonify({"error": "User does not exist"}), 400

    e = random.randrange(1, p - 1)
    challenge_db[username] = e

    return jsonify({
        "p": p,
        "g": g,
        "h": user_db[username]["h"],
        "e": e
    })

@app.route("/login/finish", methods=["POST"])
def login_finish():
    """
    Завершение логина:
    - Принимает { "username": "...", "a": "...", "y": "..." } (как строки)
    - Берёт e из challenge_db[username]
    - Проверяет g^y == a * (h^e) mod p
    - При успехе - логинит (сохраняет username в сессии)
    """
    data = request.get_json()
    username = data.get("username")
    a_str = data.get("a")
    y_str = data.get("y")

    if username not in user_db:
        return jsonify({"error": "User does not exist"}), 400

    if username not in challenge_db:
        return jsonify({"error": "No challenge for user"}), 400

    a = int(a_str)
    y = int(y_str)

    e = challenge_db[username]
    h_val = user_db[username]["h"]

    left = pow(g, y, p)
    right = (a * pow(h_val, e, p)) % p

    print("left =", left)
    print("right =", right)
    print("left == right ?", left == right)

    if left == right:
        session["username"] = username
        del challenge_db[username]  
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"error": "Verification failed"}), 401

@app.route("/protected", methods=["GET"])
def protected():
    """
    Пример защищённого ресурса,
    доступного только аутентифицированным пользователям.
    """
    if "username" in session:
        return jsonify({"message": f"You are logged in as {session['username']}!"})
    else:
        return jsonify({"error": "Not authenticated"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    """
    Завершение сессии пользователя:
    - Удаляет username из сессии.
    """
    session.clear()  # Очищаем все данные сессии
    return jsonify({"message": "Logout successful!"}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)


