import os
import hashlib
import requests
import base64
import json
from flask import Flask, request, jsonify, session, send_from_directory
from dotenv import load_dotenv

# 环境变量配置
load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=604800  # 7天
)

# GitHub 配置
CONFIG = {
    'GITHUB_TOKEN': os.getenv('GITHUB_TOKEN'),
    'REPO_OWNER': os.getenv('REPO_OWNER', 'Cpowefh'),
    'REPO_NAME': os.getenv('REPO_NAME', 'ggsig'),
    'USERS_FILE': 'users.json'
}

def api_request(method, path, data=None):
    url = f"https://api.github.com/repos/{CONFIG['REPO_OWNER']}/{CONFIG['REPO_NAME']}/contents/{path}"
    headers = {
        "Authorization": f"token {CONFIG['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        if method == 'GET':
            res = requests.get(url, headers=headers)
        elif method == 'PUT':
            res = requests.put(url, headers=headers, json=data)
        res.raise_for_status()
        return res.json() if res.content else None
    except Exception as e:
        print(f"GitHub API Error: {str(e)}")
        return None

def get_users():
    data = api_request('GET', CONFIG['USERS_FILE'])
    if data and 'content' in data:
        return json.loads(base64.b64decode(data['content']).decode('utf-8'))
    return {}

def save_users(users):
    content = base64.b64encode(json.dumps(users, indent=2).encode()).decode('utf-8')
    sha = api_request('GET', CONFIG['USERS_FILE']).get('sha') if get_users() else None
    return api_request('PUT', CONFIG['USERS_FILE'], {
        "message": "Update users",
        "content": content,
        "sha": sha
    })

# API 路由
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not all([email, username, password]):
        return jsonify({'success': False, 'message': '所有字段必填'}), 400

    users = get_users()
    if email in users:
        return jsonify({'success': False, 'message': '邮箱已注册'}), 400

    salt = os.urandom(16).hex()
    users[email] = {
        'username': username,
        'password_hash': hashlib.sha256(f"{password}{salt}".encode()).hexdigest(),
        'salt': salt,
        'email': email
    }

    return jsonify({'success': save_users(users)})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password', '').strip()

    users = get_users()
    user = users.get(email)
    if not user:
        return jsonify({'success': False, 'message': '无效凭证'}), 401

    if user['password_hash'] != hashlib.sha256(f"{password}{user['salt']}".encode()).hexdigest():
        return jsonify({'success': False, 'message': '无效凭证'}), 401

    session['user'] = {'email': email, 'username': user['username']}
    return jsonify({'success': True, 'user': session['user']})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    return jsonify({
        'authenticated': 'user' in session,
        'user': session.get('user')
    })

# 静态路由
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/?redirect=/dashboard')
    return send_from_directory('static', 'dashboard.html')

# Vercel 适配器
def vercel_handler(req):
    with app.app_context():
        return app(req)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
