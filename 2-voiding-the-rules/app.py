import os
from authlib.jose import jwt
from flask import Flask, jsonify, request, send_from_directory


app = Flask(__name__, static_folder="public", static_url_path="")

SECRET = os.urandom(16).hex()


@app.get("/")
def login_page():
    return send_from_directory("public", "index.html")


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify(error="Username is required."), 400
    if username.lower() == "admin":
        return jsonify(error="This username is not available."), 400

    token = jwt.encode({"alg": "HS256"}, {"name": username, "role": "employee"}, SECRET).decode("utf-8")
    response = jsonify(success=True)
    response.set_cookie("session", token, samesite="Strict")
    return response


@app.get("/api/me")
def me():
    token = request.cookies.get("session")
    if not token:
        return jsonify(error="Unauthenticated."), 401

    try:
        claims = jwt.decode(token, SECRET)
        return jsonify(name=claims.get("name"), role=claims.get("role"))
    except Exception:
        return jsonify(error="Invalid session."), 401


@app.get("/api/admin/data")
def admin_data():
    token = request.cookies.get("session")
    if not token:
        return jsonify(error="Unauthenticated."), 401

    try:
        claims = jwt.decode(token, SECRET)
        if claims.get("role") != "admin":
            return jsonify(error="Forbidden."), 403
        return jsonify(admin_payload())
    except Exception:
        return jsonify(error="Invalid session."), 401


def admin_payload():
    return {
        "flag": "FLAG{n0n3_5h411_p455_7h3_n0n3_ch3ck}",
        "employees": [
            {"id": 1, "name": "Sophie Bernard", "dept": "Engineering", "salary": "€72,000", "status": "Active"},
            {"id": 2, "name": "Lucas Petit", "dept": "Product", "salary": "€65,000", "status": "Active"},
            {"id": 3, "name": "Emma Rousseau", "dept": "Design", "salary": "€60,000", "status": "Active"},
            {"id": 4, "name": "Nathan Moreau", "dept": "Engineering", "salary": "€70,000", "status": "On leave"},
        ],
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
