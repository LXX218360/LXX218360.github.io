from flask import Flask, request, jsonify, send_from_directory, make_response
import json, os, random, string, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'codes.json')
DEFAULT_PASSWORD = 'lxx218360lxx'

app = Flask(__name__)

# ============================================================
# 内置CORS支持（不依赖flask_cors包）
# ============================================================

@app.after_request
def add_cors_headers(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

# ============================================================
# 数据库 + 配置管理
# ============================================================

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_db(db):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def get_admin_password():
    """从数据库读取管理员密码，如果没有则使用默认并保存"""
    db = load_db()
    config = db.get('_config', {})
    pw = config.get('admin_password')
    if not pw:
        # 首次使用，保存默认密码
        db['_config'] = {'admin_password': DEFAULT_PASSWORD}
        save_db(db)
        return DEFAULT_PASSWORD
    return pw

def set_admin_password(new_pw):
    """修改管理员密码"""
    db = load_db()
    if '_config' not in db:
        db['_config'] = {}
    db['_config']['admin_password'] = new_pw
    save_db(db)

def check_password(pw):
    """验证密码是否正确"""
    return pw == get_admin_password()

def generate_code(plan_type='lifetime'):
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    suffix = ''.join(random.choices(chars, k=6))
    part2 = ''.join(random.choices(chars, k=4))
    return f'EYE-{suffix}-{part2}'

# ============================================================
# 创作者管理面板（在线版）
# ============================================================

@app.route('/seller')
@app.route('/seller/')
def seller_panel():
    """创作者管理面板入口 - 优先使用精简版 seller.html"""
    for fname in ['seller.html', 'eye-guard-creator.html']:
        html_path = os.path.join(BASE_DIR, fname)
        if os.path.exists(html_path):
            return send_from_directory(BASE_DIR, fname)
    return '<h1>seller.html not found</h1><p>Please upload seller.html to: ' + BASE_DIR + '</p>', 404

# ============================================================
# API 接口
# ============================================================

@app.route('/api/generate', methods=['POST'])
def api_generate():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    plan = data.get('plan', 'lifetime')
    count = min(int(data.get('count', 1)), 50)
    phone = data.get('phone', '')

    db = load_db()
    # 移除配置项，只保留激活码
    codes_db = {k: v for k, v in db.items() if not k.startswith('_')}
    codes = []
    for _ in range(count):
        code = generate_code(plan)
        while code in codes_db:
            code = generate_code(plan)
        codes_db[code] = {
            'plan': plan,
            'phone': phone,
            'used': False,
            'created_at': time.time()
        }
        codes.append(code)
    # 保留配置，保存激活码
    config = db.get('_config', {})
    codes_db['_config'] = config
    save_db(codes_db)
    return jsonify({'success': True, 'codes': codes})

@app.route('/api/activate', methods=['POST'])
def api_activate():
    data = request.get_json() or {}
    code = data.get('code', '').upper()
    phone = data.get('phone', '')

    if not code or not phone:
        return jsonify({'success': False, 'msg': '参数缺失'}), 400

    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'success': False, 'msg': '激活码无效'})

    rec = db[code]

    if rec.get('phone') and rec['phone'] != phone:
        return jsonify({'success': False, 'msg': '该激活码与手机号不匹配'})

    if rec['used']:
        if rec.get('phone') == phone:
            return jsonify({'success': True, 'msg': '该手机号已激活', 'plan': rec['plan']})
        return jsonify({'success': False, 'msg': '该激活码已被其他手机号绑定'})

    existing_same_plan = 0
    for c, r in db.items():
        if not c.startswith('_') and r['used'] and r.get('phone') == phone and r['plan'] == rec['plan']:
            existing_same_plan += 1

    rec['used'] = True
    rec['phone'] = phone
    rec['activated_at'] = time.time()
    save_db(db)

    msg = '激活成功'
    if existing_same_plan > 0:
        msg = f'激活成功（该手机号已有{existing_same_plan}个相同套餐）'

    return jsonify({'success': True, 'msg': msg, 'plan': rec['plan']})

@app.route('/api/list', methods=['POST'])
def api_list():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    db = load_db()
    # 过滤掉内部配置项
    codes = {k: v for k, v in db.items() if not k.startswith('_')}
    return jsonify({'success': True, 'codes': codes})

@app.route('/api/verify', methods=['POST'])
def api_verify():
    """启动时验证激活码是否有效（用于防止本地篡改）"""
    data = request.get_json() or {}
    code = data.get('code', '').upper()
    phone = data.get('phone', '')

    if not code:
        return jsonify({'valid': False, 'msg': '参数缺失'})

    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'valid': False, 'msg': '激活码不存在'})

    rec = db[code]
    if not rec['used']:
        return jsonify({'valid': False, 'msg': '激活码未激活'})

    if phone and rec.get('phone') != phone:
        return jsonify({'valid': False, 'msg': '手机号不匹配'})

    if rec['plan'] in ('month', 'year') and rec.get('activated_at'):
        days = 30 if rec['plan'] == 'month' else 365
        expire_time = rec['activated_at'] + days * 24 * 3600
        if time.time() > expire_time:
            return jsonify({'valid': False, 'msg': '已过期'})

    return jsonify({
        'valid': True,
        'plan': rec['plan'],
        'phone': rec.get('phone', ''),
        'activated_at': rec.get('activated_at', 0)
    })


@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json() or {}
    code = data.get('code', '').upper()
    db = load_db()
    if code in db and not code.startswith('_'):
        rec = db[code]
        return jsonify({
            'exists': True,
            'used': rec['used'],
            'plan': rec['plan'],
            'phone': rec.get('phone', '')
        })
    return jsonify({'exists': False})

@app.route('/api/change_password', methods=['POST'])
def api_change_password():
    """修改管理员密码"""
    data = request.get_json() or {}
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')

    if not check_password(old_pw):
        return jsonify({'success': False, 'msg': '当前密码错误'}), 403

    if not new_pw or len(new_pw) < 4:
        return jsonify({'success': False, 'msg': '新密码至少4位'}), 400

    set_admin_password(new_pw)
    return jsonify({'success': True, 'msg': '密码修改成功'})

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'status': 'ok', 'time': time.time()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print('=' * 50)
    print('护眼精灵 Pro 后端服务')
    print('=' * 50)
    print(f'API地址: http://0.0.0.0:{port}')
    print(f'创作者面板: http://0.0.0.0:{port}/seller')
    print(f'管理密码: {get_admin_password()}')
    print(f'数据库: {DB_FILE}')
    print('=' * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
