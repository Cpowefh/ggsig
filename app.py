from flask import Flask, request, jsonify, send_from_directory
import requests
import base64
import os
import hashlib
import json

# 兼容本地开发和 Vercel 环境变量
if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

# GitHub 配置
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO_OWNER = os.getenv('REPO_OWNER', 'your-username')
REPO_NAME = os.getenv('REPO_NAME', 'your-repo')
USERS_FILE = 'users.json'
GITHUB_API = 'https://api.github.com'

headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def get_file_sha(filename):
    """获取文件SHA哈希"""
    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filename}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json().get('sha', '')
    except Exception as e:
        print(f"Error getting file SHA: {str(e)}")
        return None

def hash_password(password, salt=None):
    """密码加盐哈希"""
    salt = salt or os.urandom(16).hex()
    return {
        'hash': hashlib.sha256(f"{password}{salt}".encode()).hexdigest(),
        'salt': salt
    }

def get_users_data():
    """从GitHub获取用户数据"""
    try:
        url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{USERS_FILE}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content = base64.b64decode(response.json()['content']).decode('utf-8')
        return json.loads(content)
    except Exception as e:
        print(f"Error fetching users: {str(e)}")
        return {}

def save_users_data(users):
    """保存数据到GitHub"""
    try:
        content = json.dumps(users, indent=2)
        payload = {
            "message": "Update users",
            "content": base64.b64encode(content.encode()).decode('utf-8'),
            "sha": get_file_sha(USERS_FILE)
        }
        url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{USERS_FILE}"
        response = requests.put(url, headers=headers, json=payload)
        return response.status_code in (200, 201)
    except Exception as e:
        print(f"Error saving users: {str(e)}")
        return False

# API 路由
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    # ... [保持原有注册逻辑] ...
    return jsonify({'success': True})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    # ... [保持原有登录逻辑] ...
    return jsonify({
        'success': True,
        'token': 'generated-jwt-token'  # 实际项目应生成真实JWT
    })

# 静态文件路由
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# Vercel 适配器
def vercel_handler(request):
    with app.app_context():
        response = app.full_dispatch_request()
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
