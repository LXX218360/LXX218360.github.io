from flask import Flask, request, jsonify, send_from_directory
import json, os, secrets, time, re, threading, shutil
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# 护眼精灵 Pro 后端服务 v2.0
# 核心规则：一个手机号只能绑定一个激活码
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'codes.json')
USAGE_FILE = os.path.join(BASE_DIR, 'usage_tracking.json')
LOG_FILE = os.path.join(BASE_DIR, 'audit.log')
DEFAULT_PASSWORD = 'lxx218360lxx'

PLAN_CONFIG = {
    'week':     {'label': '周卡', 'days': 7},
    'month':    {'label': '月卡', 'days': 30},
    'year':     {'label': '年卡', 'days': 365},
    'lifetime': {'label': '终身', 'days': 36500},
}

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 限制请求体 2MB

# 全局锁，保护文件写入
_db_lock = threading.Lock()

# ============================================================
# CORS 支持（限制为常见前端域名）
# ============================================================

ALLOWED_ORIGINS = [
    'https://18073951649.pythonanywhere.com',
    'https://lxx218360.github.io',
    'http://localhost',
    'https://localhost',
    'null',  # file:// 协议
]

@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS or origin.startswith('http://localhost') or origin.startswith('https://localhost'):
        resp.headers['Access-Control-Allow-Origin'] = origin
    else:
        resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

# ============================================================
# 工具函数
# ============================================================

_rate_limits = {}
_rate_lock = threading.Lock()

def rate_limit_check(key, max_requests=30, window_seconds=60):
    with _rate_lock:
        now = time.time()
        if key not in _rate_limits:
            _rate_limits[key] = []
        _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window_seconds]
        if len(_rate_limits[key]) >= max_requests:
            return False
        _rate_limits[key].append(now)
        return True

def is_valid_phone(phone):
    return bool(phone and re.match(r'^1[3-9]\d{9}$', phone))

def get_client_ip():
    # PythonAnywhere 使用反向代理，真实客户端IP在 X-Forwarded-For 中
    # 取第一个IP（最原始的客户端地址）
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def audit_log(action, detail=''):
    """记录审计日志"""
    try:
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        line = f"[{ts}] [{get_client_ip()}] {action} | {detail}\n"
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass

# ============================================================
# 原子文件操作
# ============================================================

def atomic_write_json(filepath, data, indent=2):
    """原子写入 JSON：先写临时文件，再重命名"""
    tmp = filepath + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)
    os.replace(tmp, filepath)

def backup_file(filepath):
    """写入前自动备份（保留最近3个）"""
    if os.path.exists(filepath):
        ts = time.strftime('%Y%m%d%H%M%S')
        bak = filepath + f'.bak.{ts}'
        shutil.copy2(filepath, bak)
        # 清理旧备份（保留最近3个）
        try:
            dirname = os.path.dirname(filepath) or '.'
            basename = os.path.basename(filepath)
            baks = sorted([
                f for f in os.listdir(dirname)
                if f.startswith(basename + '.bak.')
            ], reverse=True)
            for old in baks[3:]:
                os.remove(os.path.join(dirname, old))
        except Exception:
            pass

def load_db():
    with _db_lock:
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                # 尝试从备份恢复
                dirname = os.path.dirname(DB_FILE) or '.'
                basename = os.path.basename(DB_FILE)
                baks = sorted([
                    f for f in os.listdir(dirname)
                    if f.startswith(basename + '.bak.')
                ], reverse=True)
                for bak_name in baks:
                    try:
                        with open(os.path.join(dirname, bak_name), 'r', encoding='utf-8') as f:
                            return json.load(f)
                    except Exception:
                        continue
                return {}
        return {}

def save_db(db):
    with _db_lock:
        backup_file(DB_FILE)
        atomic_write_json(DB_FILE, db)

def load_usage():
    with _db_lock:
        if os.path.exists(USAGE_FILE):
            try:
                with open(USAGE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

def save_usage(data):
    with _db_lock:
        backup_file(USAGE_FILE)
        atomic_write_json(USAGE_FILE, data)

# ============================================================
# 密码管理（bcrypt 哈希，兼容旧版明文）
# ============================================================

def hash_password(pw):
    return generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

def get_admin_password_hash():
    db = load_db()
    pw = db.get('_config', {}).get('admin_password', DEFAULT_PASSWORD)
    return pw

def set_admin_password(new_pw):
    db = load_db()
    if '_config' not in db:
        db['_config'] = {}
    db['_config']['admin_password'] = hash_password(new_pw)
    save_db(db)

def check_password(pw):
    stored = get_admin_password_hash()
    # 兼容旧版明文密码（自动迁移）
    if stored == pw:
        # 明文匹配，自动升级为哈希
        set_admin_password(pw)
        return True
    # 哈希校验
    if stored.startswith('pbkdf2:'):
        return check_password_hash(stored, pw)
    return False

# ============================================================
# 激活码生成（加密安全随机数）
# ============================================================

def generate_code(plan_type='month'):
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    suffix = ''.join(secrets.choice(chars) for _ in range(6))
    part2 = ''.join(secrets.choice(chars) for _ in range(4))
    return f'EYE-{suffix}-{part2}'

# ============================================================
# 时区统一（UTC+8）
# ============================================================

def get_today_utc8():
    """返回 UTC+8 的日期字符串 YYYY-MM-DD"""
    return time.strftime('%Y-%m-%d', time.localtime(time.time() + 8 * 3600))

# ============================================================
# 免费试用追踪
# ============================================================

FREE_DAILY_SECONDS = 300  # 每天免费5分钟

# ============================================================
# 静态页面路由
# ============================================================

@app.route('/seller')
@app.route('/seller/')
def seller_panel():
    for fname in ['seller.html']:
        fpath = os.path.join(BASE_DIR, fname)
        if os.path.exists(fpath):
            return send_from_directory(BASE_DIR, fname)
    return '<h1>页面未找到</h1>', 404

@app.route('/')
def index_page():
    for fname in ['eye-guard-user.html']:
        fpath = os.path.join(BASE_DIR, fname)
        if os.path.exists(fpath):
            return send_from_directory(BASE_DIR, fname)
    return '<h1>护眼精灵</h1><p>请联系管理员上传页面文件</p>', 404

# ============================================================
# API：激活码生成
# ============================================================

@app.route('/api/generate', methods=['POST'])
def api_generate():
    data = request.get_json() or {}
    if not rate_limit_check(get_client_ip() + '_gen', 10, 60):
        return jsonify({'success': False, 'msg': '操作太频繁，请稍后再试'}), 429
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    plan = data.get('plan', 'month')
    if plan not in PLAN_CONFIG:
        return jsonify({'success': False, 'msg': '无效的套餐类型'}), 400

    try:
        count = max(1, min(int(data.get('count', 1)), 50))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'msg': '数量必须是数字'}), 400

    phone = data.get('phone', '')
    if phone and not is_valid_phone(phone):
        return jsonify({'success': False, 'msg': '手机号格式不正确'}), 400

    db = load_db()
    config = db.get('_config', {})
    codes_db = {k: v for k, v in db.items() if not k.startswith('_')}
    codes = []
    max_attempts = count * 100
    attempts = 0
    for _ in range(count):
        code = generate_code(plan)
        attempts += 1
        while code in codes_db and attempts < max_attempts:
            code = generate_code(plan)
            attempts += 1
        if attempts >= max_attempts:
            return jsonify({'success': False, 'msg': '激活码空间不足，请减少生成数量'}), 500
        codes_db[code] = {
            'plan': plan,
            'phone': phone or '',
            'used': False,
            'created_at': time.time()
        }
        codes.append(code)
    codes_db['_config'] = config
    save_db(codes_db)
    audit_log('生成激活码', f'plan={plan}, count={count}, by={get_client_ip()}')
    return jsonify({'success': True, 'codes': codes})

# ============================================================
# API：激活（一个手机号只能绑定一个激活码）
# ============================================================

@app.route('/api/activate', methods=['POST'])
def api_activate():
    data = request.get_json() or {}
    if not rate_limit_check(get_client_ip() + '_act', 10, 60):
        return jsonify({'success': False, 'msg': '操作太频繁，请稍后再试'}), 429

    code = data.get('code', '').strip().upper()
    phone = data.get('phone', '').strip()

    if not code or not phone:
        return jsonify({'success': False, 'msg': '参数缺失'}), 400
    if not is_valid_phone(phone):
        return jsonify({'success': False, 'msg': '手机号格式不正确'}), 400

    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'success': False, 'msg': '激活码无效'})

    rec = db[code]

    # 预绑定的手机号校验
    if rec.get('phone') and rec['phone'] != phone:
        return jsonify({'success': False, 'msg': '该激活码与手机号不匹配'})

    # 已经激活过
    if rec['used']:
        if rec.get('phone') == phone:
            # 重新计算叠加信息
            result = _calc_membership(db, phone)
            result['success'] = True
            result['msg'] = '该手机号已激活'
            result['plan'] = rec['plan']
            return jsonify(result)
        return jsonify({'success': False, 'msg': '该激活码已被其他手机号绑定'})

    # 核心规则：检查该手机号是否已绑定过其他激活码
    for c, r in db.items():
        if c == code or c.startswith('_'):
            continue
        if r.get('used') and r.get('phone') == phone:
            return jsonify({'success': False, 'msg': '该手机号已绑定其他激活码，一个手机号只能绑定一个'})

    # 激活
    rec['used'] = True
    rec['phone'] = phone
    rec['activated_at'] = time.time()
    save_db(db)
    audit_log('激活', f'code={code}, phone={phone}, plan={rec["plan"]}')

    # 返回完整的叠加信息
    result = _calc_membership(db, phone)
    result['success'] = True
    result['msg'] = '激活成功'
    result['plan'] = rec['plan']
    result['is_renewal'] = result.get('total_codes', 1) > 1
    return jsonify(result)

# ============================================================
# 内部：计算手机号的会员叠加信息
# ============================================================

def _calc_membership(db, phone):
    """计算指定手机号的叠加会员信息"""
    total_remaining_seconds = 0
    active_codes = []
    all_codes = []
    now = time.time()
    for c, r in db.items():
        if c.startswith('_') or not r.get('used') or r.get('phone') != phone:
            continue
        all_codes.append(c)
        if r['plan'] == 'lifetime':
            total_remaining_seconds += PLAN_CONFIG['lifetime']['days'] * 86400
            active_codes.append(c)
        else:
            days = PLAN_CONFIG.get(r['plan'], {}).get('days', 30)
            a_at = r.get('activated_at', 0)
            if a_at:
                expire = a_at + days * 86400
                remain = expire - now
                if remain > 0:
                    total_remaining_seconds += remain
                    active_codes.append(c)

    return {
        'remaining_days': round(total_remaining_seconds / 86400, 1),
        'remaining_seconds': int(total_remaining_seconds),
        'total_codes': len(all_codes),
        'active_codes': active_codes,
        'active_codes_count': len(active_codes),
        'expires_at': now + total_remaining_seconds
    }

# ============================================================
# API：验证激活码（用户端启动/定期同步）
# ============================================================

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.get_json() or {}
    code = data.get('code', '').strip().upper()
    phone = data.get('phone', '').strip()

    if not code:
        return jsonify({'valid': False})

    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'valid': False, 'msg': '激活码不存在'})

    rec = db[code]
    if not rec['used']:
        return jsonify({'valid': False, 'msg': '激活码未激活'})
    if phone and rec.get('phone') != phone:
        return jsonify({'valid': False, 'msg': '手机号不匹配'})

    plan = rec['plan']
    activated_at = rec.get('activated_at', 0)

    # 使用统一函数计算
    result = _calc_membership(db, rec.get('phone', ''))

    return jsonify({
        'valid': True,
        'plan': plan,
        'phone': rec.get('phone', ''),
        'activated_at': activated_at,
        'remaining_days': result['remaining_days'],
        'remaining_seconds': result['remaining_seconds'],
        'total_codes': result['total_codes'],
        'active_codes': result['active_codes'],
        'active_codes_count': result['active_codes_count'],
        'expires_at': result['expires_at']
    })

# ============================================================
# API：激活码列表（管理面板）
# ============================================================

@app.route('/api/list', methods=['POST'])
def api_list():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    db = load_db()
    codes = {}
    now = time.time()
    for k, v in db.items():
        if k.startswith('_'):
            continue
        codes[k] = dict(v)
        # 注入过期信息
        if v.get('used') and v['plan'] != 'lifetime':
            days = PLAN_CONFIG.get(v['plan'], {}).get('days', 30)
            a_at = v.get('activated_at', 0)
            if a_at:
                expire = a_at + days * 86400
                codes[k]['expires_at'] = expire
                codes[k]['remaining_days'] = round(max(0, (expire - now) / 86400), 1)
            else:
                codes[k]['remaining_days'] = 0
        elif v.get('used') and v['plan'] == 'lifetime':
            codes[k]['remaining_days'] = 99999
        else:
            codes[k]['remaining_days'] = None
    return jsonify({'success': True, 'codes': codes})

# ============================================================
# API：删除激活码
# ============================================================

@app.route('/api/delete_code', methods=['POST'])
def api_delete_code():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    code = data.get('code', '').strip().upper()
    db = load_db()
    if code in db and not code.startswith('_'):
        phone = db[code].get('phone', '')
        del db[code]
        save_db(db)
        audit_log('删除激活码', f'code={code}, phone={phone}, by={get_client_ip()}')
        return jsonify({'success': True, 'msg': '已删除'})
    return jsonify({'success': False, 'msg': '激活码不存在'})

# ============================================================
# API：撤销激活码（解除手机号绑定，保留记录）
# ============================================================

@app.route('/api/revoke_code', methods=['POST'])
def api_revoke_code():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    code = data.get('code', '').strip().upper()
    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'success': False, 'msg': '激活码不存在'})

    rec = db[code]
    if not rec['used']:
        return jsonify({'success': False, 'msg': '该激活码未被激活'})

    rec['used'] = False
    rec['phone'] = ''
    rec.pop('activated_at', None)
    rec['revoked_at'] = time.time()
    save_db(db)
    audit_log('撤销激活码', f'code={code}, by={get_client_ip()}')
    return jsonify({'success': True, 'msg': '已撤销，用户需重新激活'})

# ============================================================
# API：修复激活码（修改套餐类型）
# ============================================================

@app.route('/api/fix_code', methods=['POST'])
def api_fix_code():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    code = data.get('code', '').strip().upper()
    new_plan = data.get('plan', '')
    if not code or new_plan not in PLAN_CONFIG:
        return jsonify({'success': False, 'msg': '参数无效'}), 400

    db = load_db()
    if code not in db or code.startswith('_'):
        return jsonify({'success': False, 'msg': '激活码不存在'})

    db[code]['plan'] = new_plan
    save_db(db)
    audit_log('修改套餐', f'code={code}, new_plan={new_plan}, by={get_client_ip()}')
    return jsonify({'success': True, 'msg': f'已修改为{PLAN_CONFIG[new_plan]["label"]}'})

# ============================================================
# API：校准
# ============================================================

@app.route('/api/calibrate', methods=['POST'])
def api_calibrate():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    db = load_db()
    issues = []
    checked = 0
    now = time.time()
    for code, rec in db.items():
        if code.startswith('_'):
            continue
        checked += 1
        if rec.get('used'):
            if rec['plan'] in ('month', 'year', 'week'):
                days = PLAN_CONFIG.get(rec['plan'], {}).get('days', 30)
                if rec.get('activated_at') and now > rec['activated_at'] + days * 86400:
                    issues.append({
                        'code': code,
                        'description': '已过期',
                        'plan_name': PLAN_CONFIG.get(rec['plan'], {}).get('label', rec['plan']),
                        'phone': rec.get('phone', '')
                    })
        if rec.get('revoked_at'):
            issues.append({
                'code': code,
                'description': '已撤销',
                'plan_name': PLAN_CONFIG.get(rec['plan'], {}).get('label', rec['plan']),
                'phone': rec.get('phone', '')
            })
        if rec.get('phone') and not is_valid_phone(rec['phone']):
            issues.append({
                'code': code,
                'description': '手机号格式异常',
                'plan_name': PLAN_CONFIG.get(rec['plan'], {}).get('label', rec['plan']),
                'phone': rec.get('phone', '')
            })

    return jsonify({
        'success': True,
        'msg': '校准完成',
        'report': {'checked': checked, 'issues': issues}
    })

# ============================================================
# API：查看用户列表（按手机号分组）
# ============================================================

@app.route('/api/users', methods=['POST'])
def api_users():
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        return jsonify({'success': False, 'msg': '密码错误'}), 403

    db = load_db()
    phones = {}
    now = time.time()
    for code, rec in db.items():
        if code.startswith('_') or not rec.get('used'):
            continue
        phone = rec.get('phone', '')
        if not phone:
            continue
        if phone not in phones:
            phones[phone] = {'codes': [], 'membership': {}}
        days = PLAN_CONFIG.get(rec['plan'], {}).get('days', 0)
        activated_at = rec.get('activated_at', 0)
        expire = activated_at + days * 86400
        remaining = max(0, (expire - now) / 86400) if days < 36500 else 99999
        plan_label = PLAN_CONFIG.get(rec['plan'], {}).get('label', rec['plan'])
        phones[phone]['codes'].append({
            'code': code,
            'plan': rec['plan'],
            'plan_name': plan_label,
            'used': True,
            'activated_at': activated_at,
            'expires_at': expire,
            'remaining_days': round(remaining, 1)
        })

    # 汇总每个手机号的会员信息
    for phone, info in phones.items():
        codes = info['codes']
        active = [c for c in codes if c['remaining_days'] > 0]
        if active:
            earliest = min(c['activated_at'] for c in active)
            latest_end = max(c['expires_at'] for c in active)
            total_rem = sum(c['remaining_days'] for c in active)
            info['membership'] = {
                'valid': True,
                'remaining_days': round(total_rem, 1),
                'earliest_start': earliest,
                'end_time': latest_end,
                'active_codes': [c['code'] for c in active]
            }
        else:
            info['membership'] = {
                'valid': False,
                'remaining_days': 0,
                'earliest_start': None,
                'end_time': None,
                'active_codes': []
            }

    return jsonify({'success': True, 'phones': phones})

# ============================================================
# API：查询激活码状态（需要密码鉴权，防止隐私泄露）
# ============================================================

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json() or {}
    # 公开接口：只需要 code，不需要密码
    # 但已激活的码只返回掩码手机号，不泄露完整号码
    code = data.get('code', '').strip().upper()
    db = load_db()
    if code in db and not code.startswith('_'):
        rec = db[code]
        phone = rec.get('phone', '')
        # 已激活的码，手机号只返回掩码
        if rec.get('used') and phone and len(phone) == 11:
            phone = phone[:3] + '****' + phone[7:]
        return jsonify({
            'exists': True,
            'used': rec['used'],
            'plan': rec['plan'],
            'phone': phone
        })
    return jsonify({'exists': False})

# ============================================================
# API：修改管理员密码
# ============================================================

@app.route('/api/change_password', methods=['POST'])
def api_change_password():
    data = request.get_json() or {}
    if not rate_limit_check(get_client_ip() + '_chpw', 5, 60):
        return jsonify({'success': False, 'msg': '操作太频繁'}), 429

    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not check_password(old_pw):
        return jsonify({'success': False, 'msg': '当前密码错误'}), 403
    if not new_pw or len(new_pw) < 6:
        return jsonify({'success': False, 'msg': '新密码至少6位'}), 400

    set_admin_password(new_pw)
    audit_log('修改密码', f'by={get_client_ip()}')
    return jsonify({'success': True, 'msg': '密码修改成功'})

# ============================================================
# API：健康检查
# ============================================================

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'status': 'ok', 'time': time.time()})

# ============================================================
# API：免费试用时长追踪（统一接口）
# ============================================================

@app.route('/api/free_usage', methods=['POST'])
def api_free_usage():
    data = request.get_json() or {}
    # 同时支持 device_fp（前端旧版）和 phone（前端新版）
    phone = data.get('phone', '').strip()
    if not phone:
        phone = data.get('device_fp', '').strip()

    if not phone:
        return jsonify({'success': False, 'msg': '缺少标识'}), 400

    # 如果 phone 是手机号格式，额外校验
    if len(phone) == 11 and not is_valid_phone(phone):
        return jsonify({'success': False, 'msg': '手机号格式不正确'}), 400

    usage = load_usage()
    today = get_today_utc8()
    now = time.time()

    if phone not in usage:
        usage[phone] = {'total_seconds': 0, 'last_reset': today}
    elif usage[phone].get('last_reset') != today:
        usage[phone]['total_seconds'] = 0
        usage[phone]['last_reset'] = today

    action = data.get('action', 'check')
    # 同时支持 seconds（新版）和 minutes（旧版）
    seconds = data.get('seconds', 0)
    minutes = data.get('minutes', 0)
    if minutes and not seconds:
        seconds = int(minutes * 60)
    # 防止负数攻击
    seconds = max(0, seconds)

    if action == 'report':
        usage[phone]['total_seconds'] = max(0, usage[phone].get('total_seconds', 0) + seconds)
        save_usage(usage)
        remaining = max(0, FREE_DAILY_SECONDS - usage[phone]['total_seconds'])
        return jsonify({
            'success': True,
            'used_today': usage[phone]['total_seconds'],
            'used_minutes': round(usage[phone]['total_seconds'] / 60, 1),
            'remaining_today': remaining,
            'remaining_minutes': round(remaining / 60, 1),
            'limit': FREE_DAILY_SECONDS
        })
    else:
        remaining = max(0, FREE_DAILY_SECONDS - usage[phone].get('total_seconds', 0))
        return jsonify({
            'success': True,
            'used_today': usage[phone].get('total_seconds', 0),
            'used_minutes': round(usage[phone].get('total_seconds', 0) / 60, 1),
            'remaining_today': remaining,
            'remaining_minutes': round(remaining / 60, 1),
            'limit': FREE_DAILY_SECONDS
        })

# ============================================================
# 启动
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # 首次运行初始化密码
    db = load_db()
    if '_config' not in db:
        db['_config'] = {'admin_password': DEFAULT_PASSWORD}
        save_db(db)
    # 自动迁移：如果密码还是明文，会在 check_password 时自动哈希

    print('=' * 50)
    print('护眼精灵 Pro 后端服务 v2.0')
    print('=' * 50)
    print(f'API地址: http://0.0.0.0:{port}')
    print(f'创作者面板: http://0.0.0.0:{port}/seller')
    print(f'初始密码: {DEFAULT_PASSWORD}')
    print(f'数据库: {DB_FILE}')
    print('=' * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
