from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, g, redirect, request, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

# =========================
# Config
# =========================
APP_SECRET = os.environ.get("APP_SECRET_KEY", "CHANGE_ME__PLEASE_SET_ENV_APP_SECRET_KEY")
DB_PATH = os.environ.get("APP_DB_PATH", os.path.join(os.path.dirname(__file__), "auth.db"))

app = Flask(__name__)
app.secret_key = APP_SECRET
app.permanent_session_lifetime = timedelta(days=7)


# =========================
# DB
# =========================
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    db.commit()

    def ensure_user(username: str, password: str, role: str):
        row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                (username, generate_password_hash(password), role),
            )
            db.commit()

    ensure_user("admin", os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123"), "admin")
    ensure_user("user", os.environ.get("DEFAULT_USER_PASSWORD", "user123"), "user")


@app.before_request
def _ensure_db():
    init_db()


# =========================
# Auth helpers
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            nxt = request.path or "/"
            return redirect(f"/login?next={nxt}")
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            nxt = request.path or "/"
            return redirect(f"/login?next={nxt}")
        if session.get("role") != "admin":
            return Response("Forbidden", status=403)
        return fn(*args, **kwargs)

    return wrapper


def current_user():
    if "uid" not in session:
        return None
    db = get_db()
    return db.execute("SELECT id, username, role FROM users WHERE id=?", (session["uid"],)).fetchone()


# =========================
# UI & PWA Config
# =========================
FONT_LINKS = r"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto+Condensed:wght@400;700&family=Roboto:wght@400;700&display=swap" rel="stylesheet">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#07101f">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="apple-touch-icon" href="https://cdn-icons-png.flaticon.com/512/2928/2928883.png">
"""

BASE_CSS = r"""
<style>
  :root{
    --bg:#07101f;
    --card: rgba(255,255,255,.04);
    --fg:#e6eefc;
    --muted:#9bb0d0;
    --accent:#66a6ff;
    --ok:#38d996;
    --danger:#ff6b6b;
  }
  *{ box-sizing:border-box; -webkit-tap-highlight-color: transparent; }
  body{ margin:0; background:var(--bg); color:var(--fg); font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding-bottom: 20px;}
  a{ color:#bcd3ff; text-decoration:none; }
  a:hover{ text-decoration:underline; }
  header{
    padding:14px 14px; border-bottom:1px solid rgba(255,255,255,.08);
    display:flex; justify-content:space-between; align-items:center; gap:12px;
    position: sticky; top:0; background: var(--bg); z-index: 100;
  }
  header h1{ font-size:16px; margin:0; font-weight:800; color:#dbe7ff;}
  .badge{ display:inline-flex; padding:3px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.15); font-size:11px; color:#cfe0ff; }
  .wrap{ display:grid; grid-template-columns: 360px 1fr; gap:14px; padding:14px; }
  .panel{ background:var(--card); border:1px solid rgba(255,255,255,.08); border-radius:12px; padding:12px; height:fit-content; }
  .panel h2{ margin:0 0 10px 0; font-size:13px; color:#eaf2ff; text-transform: uppercase; letter-spacing: 0.5px; }
  label{ display:block; font-size:12px; color:var(--muted); margin:10px 0 6px; }
  input[type="text"], input[type="password"], input[type="time"], input[type="date"], select{
    width:100%; padding:12px 10px; border-radius:10px;
    border:1px solid rgba(255,255,255,.12);
    background:rgba(0,0,0,.25); color:var(--fg); outline:none; font-size: 16px; /* Prevent zoom on iOS */
  }
  .row{ display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
  .btns{ display:flex; flex-wrap:wrap; gap:10px; margin-top:12px; }
  button{
    border:0; border-radius:10px; padding:12px 16px; cursor:pointer;
    font-weight:700; color:#07101f; background:var(--accent);
    font-size: 14px; flex-grow: 1; text-align: center;
  }
  button.secondary{ background:rgba(255,255,255,.12); color:var(--fg); border:1px solid rgba(255,255,255,.12); }
  button.ok{ background:var(--ok); color:#04130b; }
  button.danger{ background:var(--danger); color:#220505; }
  .hint{ font-size:12px; color:var(--muted); margin-top:8px; line-height:1.35; }
  .stage{
    background:rgba(255,255,255,.03);
    border:1px dashed rgba(255,255,255,.18);
    border-radius:12px;
    padding:12px;
    min-height: 50vh;
    display:flex;
    align-items:flex-start;
    justify-content:center;
    overflow:auto;
  }
  canvas{ max-width:100%; height:auto; border-radius:10px; background:#000; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
  .toolbox{ margin-top:10px; padding:10px; border-radius:10px; border:1px solid rgba(255,255,255,.10); background:rgba(255,255,255,.03); }
  .inline{ display:flex; gap:8px; align-items:center; }
  .inline input[type="range"]{ width:100%; }
  .center{ max-width:420px; margin:40px auto; padding:0 14px; }
  .card{ background:var(--card); border:1px solid rgba(255,255,255,.08); border-radius:14px; padding:14px; }
  .msg{ margin-top:10px; padding:10px; border-radius:10px; border:1px solid rgba(255,255,255,.12); background:rgba(0,0,0,.18); font-size:12px; color:#dbe7ff; }
  table{ width:100%; border-collapse:collapse; margin-top:10px; }
  th, td{ text-align:left; font-size:12px; padding:8px 6px; border-bottom:1px solid rgba(255,255,255,.08); }
  th{ color:#cfe0ff; }
  
  /* Camera modal */
  .modal{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:9999; align-items:center; justify-content:center; }
  .modal.active{ display:flex; }
  .modal-content{ background:var(--card); border:1px solid rgba(255,255,255,.12); border-radius:12px; padding:20px; width:90%; max-width: 500px; max-height:90%; overflow:auto; display:flex; flex-direction: column; }
  video{ width:100%; border-radius:10px; background:#000; object-fit: cover; aspect-ratio: 3/4; }
  
  @media (max-width: 768px) {
    .wrap{ grid-template-columns: 1fr; }
    .panel{ position:static; }
    .stage { min-height: auto; }
    h1 { font-size: 18px; }
  }
</style>
"""


def render_page(title: str, body_html: str, user_row=None) -> str:
    right_html = ""
    if user_row is not None:
        right_html = (
            f'<span class="badge">{user_row["username"]}</span>'
            ' <a class="badge" href="/logout">Thoát</a>'
        )
        if user_row["role"] == "admin":
            right_html += ' <a class="badge" href="/admin">Admin</a>'

    return (
        "<!doctype html><html lang='vi'><head>"
        "<meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'/>"
        f"<title>{title}</title>"
        f"{FONT_LINKS}{BASE_CSS}"
        "</head><body>"
        "<header>"
        f"<h1>{title}</h1>"
        f"<div style='display:flex; gap:8px; align-items:center; flex-wrap:wrap'>{right_html}</div>"
        "</header>"
        f"{body_html}"
        "</body></html>"
    )

# =========================
# Manifest for PWA (Mobile App Mode)
# =========================
@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "TimeMark Editor",
        "short_name": "TimeMark",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#07101f",
        "theme_color": "#07101f",
        "icons": [
            {
                "src": "https://cdn-icons-png.flaticon.com/512/2928/2928883.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "https://cdn-icons-png.flaticon.com/512/2928/2928883.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    })

# =========================
# Login / Logout
# =========================
@app.get("/login")
def login():
    msg = request.args.get("msg", "")
    nxt = request.args.get("next", "/")
    body = (
        "<div class='center'><div class='card'>"
        "<h2 style='margin:0 0 8px 0; font-size:14px;'>Đăng nhập</h2>"
        "<form method='post' action='/login'>"
        f"<input type='hidden' name='next' value='{nxt}'>"
        "<label>Tài khoản</label>"
        "<input name='username' type='text' autocomplete='username' required>"
        "<label>Mật khẩu</label>"
        "<input name='password' type='password' autocomplete='current-password' required>"
        "<div class='btns'><button class='ok' type='submit'>Đăng nhập</button></div>"
        "<div class='hint'>Mặc định: <b>admin/admin123</b> · <b>user/user123</b></div>"
        + (f"<div class='msg'>{msg}</div>" if msg else "")
        + "</form></div></div>"
    )
    return Response(render_page("Login", body), mimetype="text/html; charset=utf-8")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    nxt = request.form.get("next") or "/"

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username=?",
        (username,),
    ).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        return redirect(f"/login?msg=Sai+t%C3%A0i+kho%E1%BA%A3n+ho%E1%BA%B7c+m%E1%BA%ADt+kh%E1%BA%A9u&next={nxt}")

    session.permanent = True
    session["uid"] = int(row["id"])
    session["username"] = row["username"]
    session["role"] = row["role"]
    return redirect(nxt)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login?msg=%C4%90%C3%A3+%C4%91%C4%83ng+xu%E1%BA%A5t")


# =========================
# Main app: GHÉP ẢNH + overlay auto-căn + CAMERA
# =========================
INDEX_HTML = r"""
<div class="wrap">
  <div class="panel">
    <h2>1. Thêm ảnh</h2>
    <div class="btns" style="margin-top:0;">
       <button class="secondary" onclick="document.getElementById('file').click()">📂 Chọn ảnh</button>
       <button class="secondary" id="openCamera">📷 Chụp mới</button>
    </div>
    <input id="file" type="file" accept="image/*" style="display:none;" />
    
    <h2 style="margin-top:20px;">2. Thông tin</h2>
    <div class="row">
      <div>
        <label>Giờ</label>
        <input id="time" type="time" value="05:37" />
      </div>
      <div>
        <label>Ngày</label>
        <input id="date" type="date" />
      </div>
    </div>

    <div class="row">
      <div>
        <label>Thứ</label>
        <select id="dow">
          <option value="Chủ Nhật">Chủ Nhật</option>
          <option value="Thứ Hai">Thứ Hai</option>
          <option value="Thứ Ba">Thứ Ba</option>
          <option value="Thứ Tư">Thứ Tư</option>
          <option value="Thứ Năm" selected>Thứ Năm</option>
          <option value="Thứ Sáu">Thứ Sáu</option>
          <option value="Thứ Bảy">Thứ Bảy</option>
        </select>
      </div>
    </div>

    <h2 style="margin-top:20px;">3. Xóa chữ cũ</h2>
    <div class="btns" style="margin-top:0">
      <button class="secondary" id="toggleMask">🖌️ Bật bút xóa</button>
      <button class="secondary" id="clearMask">↩️ Hoàn tác</button>
    </div>

    <div class="toolbox" id="maskBox" style="display:none;">
      <div class="inline">
        <span style="font-size:12px;color:var(--muted);min-width:60px;">Cỡ bút</span>
        <input id="brush" type="range" min="10" max="140" value="55" />
        <span class="badge" id="brushVal">55</span>
      </div>
      <div class="hint">Tô vào phần chữ cũ trên ảnh để làm mờ.</div>
    </div>

    <h2 style="margin-top:20px;">4. Xuất ảnh</h2>
    <div class="btns" style="margin-top:0">
      <button class="ok" id="render">⚡ Ghép Overlay</button>
      <button id="download" class="secondary">⬇️ Tải về</button>
      <button class="danger" id="reset">❌ Reset</button>
    </div>

    <div class="msg" id="status">Sẵn sàng</div>
  </div>

  <div class="stage">
    <canvas id="cv"></canvas>
  </div>
</div>

<!-- Camera Modal -->
<div class="modal" id="cameraModal">
  <div class="modal-content">
    <h2 style="margin:0 0 12px 0; font-size:14px;">Chụp ảnh</h2>
    <video id="video" autoplay playsinline></video>
    <div class="btns">
      <button class="ok" id="capture">📸 Chụp</button>
      <button class="secondary" id="closeCamera">Đóng</button>
    </div>
  </div>
</div>

<script>
  const $ = (id) => document.getElementById(id);
  const cv = $("cv");
  const ctx = cv.getContext("2d");
  const statusEl = $("status");

  let img = new Image();
  let hasImage = false;
  let originalBitmap = null;

  // mask (che chữ cũ)
  let maskEnabled = false;
  let isPainting = false;
  const maskCanvas = document.createElement("canvas");
  const maskCtx = maskCanvas.getContext("2d");

  // camera
  let stream = null;

  function setStatus(t){ statusEl.textContent = t; }
  function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }

  function fitCanvasToImage(w,h){
    // Mobile optimization: scale down if image is too huge
    const MAX_DIM = 2500;
    if (w > MAX_DIM || h > MAX_DIM) {
        const ratio = Math.min(MAX_DIM/w, MAX_DIM/h);
        w = Math.round(w * ratio);
        h = Math.round(h * ratio);
    }
    
    cv.width = w; cv.height = h;
    maskCanvas.width = w; maskCanvas.height = h;
    maskCtx.clearRect(0,0,w,h);
  }

  function formatDateDDMMYYYY(iso){
    if(!iso) return "";
    const parts = iso.split("-");
    if(parts.length !== 3) return "";
    const y = parts[0];
    const m = String(parts[1]).padStart(2,'0');
    const d = String(parts[2]).padStart(2,'0');
    return `${d}/${m}/${y}`;
  }

  function fitFontToWidth(ctx, text, fontTemplateFn, startSize, minSize, maxWidth){
    let size = startSize;
    while(size > minSize){
      ctx.font = fontTemplateFn(size);
      if(ctx.measureText(text).width <= maxWidth) return size;
      size -= 1;
    }
    return minSize;
  }

  function maskHasSomething(){
    const w = maskCanvas.width, h = maskCanvas.height;
    if(!w || !h) return false;
    const d = maskCtx.getImageData(0,0,w,h).data;
    for(let i=3;i<d.length;i+=4){
      if(d[i] > 0) return true;
    }
    return false;
  }

  function drawBase(){
    ctx.clearRect(0,0,cv.width,cv.height);
    // Draw scaled image
    ctx.drawImage(img, 0, 0, cv.width, cv.height);

    if(maskHasSomething()){
      const w = cv.width, h = cv.height;

      // blur giả: downscale/upscale
      const small = document.createElement("canvas");
      const scale = 0.15;
      small.width = Math.max(1, Math.floor(w*scale));
      small.height = Math.max(1, Math.floor(h*scale));
      const sctx = small.getContext("2d");
      sctx.imageSmoothingEnabled = true;
      sctx.drawImage(img,0,0,cv.width,cv.height,0,0,small.width,small.height);

      const blur = document.createElement("canvas");
      blur.width = w; blur.height = h;
      const bctx = blur.getContext("2d");
      bctx.imageSmoothingEnabled = true;
      bctx.drawImage(small,0,0,small.width,small.height,0,0,w,h);

      bctx.globalCompositeOperation = "destination-in";
      bctx.drawImage(maskCanvas,0,0);

      ctx.drawImage(blur,0,0);
    }
  }

  // Left cluster: layout giống ảnh mẫu
  function drawLeftCluster(ctx, W, H, reservedRight, timeVal, dateText, dowText){
    const BASE = Math.min(W,H);

    const leftMaxWidth = Math.round(W * 0.60);
    const leftX = clamp(Math.round(W * 0.03), 10, 42);
    const bottomPad = clamp(Math.round(H * 0.04), 10, 70);

    const rightLimit = Math.min(leftX + leftMaxWidth, W - reservedRight);
    const maxWidth = Math.max(150, rightLimit - leftX);

    const shadowBlur = Math.round(BASE * 0.004);

    const addr1 = "268B Võ Nguyên Giáp, Bắc Mỹ Phú, Ngũ";
    const addr2 = "Hành Sơn, Đà Nẵng 550000";

    let addrFont = clamp(Math.round(BASE * 0.040), 12, 34);
    const addrTpl = (s)=>`400 ${s}px "Roboto Condensed", Roboto, Arial, sans-serif`;
    addrFont = fitFontToWidth(ctx, addr1, addrTpl, addrFont, 10, maxWidth);

    const addrLineH = Math.round(addrFont * 1.18);
    const addrBlockH = addrLineH * 2;
    const gapMetaToAddr = clamp(Math.round(BASE * 0.030), 10, 36);

    let timeFont = clamp(Math.round(BASE * 0.085), 28, 82);
    const timeTpl = (s)=>`700 ${s}px "Roboto Condensed", Roboto, Arial, sans-serif`;
    const minMetaW = Math.round(maxWidth * 0.34);
    const maxTimeW = Math.max(80, maxWidth - minMetaW);
    timeFont = fitFontToWidth(ctx, timeVal, timeTpl, timeFont, 18, maxTimeW);

    const timeScaleY = 1.50;

    let metaFont = clamp(Math.round(timeFont * 0.40), 10, 36);
    const metaTpl = (s)=>`400 ${s}px "Roboto Condensed", Roboto, Arial, sans-serif`;

    const addrBottomY = H - bottomPad;
    const timeBaselineY = addrBottomY - addrBlockH - gapMetaToAddr;

    ctx.save();
    ctx.font = timeTpl(timeFont);
    const timeW = ctx.measureText(timeVal).width;
    ctx.restore();

    const gapX = clamp(Math.round(BASE * 0.018), 8, 22);
    const lineX = leftX + timeW + gapX;

    const asc = 0.80;
    const desc = 0.10;
    const lineTop    = timeBaselineY - Math.round(timeFont * asc  * timeScaleY);
    const lineBottom = timeBaselineY + Math.round(timeFont * desc * timeScaleY);
    const metaX = lineX + gapX;
    const metaMaxW = Math.max(80, rightLimit - metaX);
    const longer = (dateText.length >= dowText.length) ? dateText : dowText;
    metaFont = fitFontToWidth(ctx, longer, metaTpl, metaFont, 10, metaMaxW);

    const metaPad = Math.round(metaFont * 0.12);
    const dateY = lineTop + metaFont + metaPad;
    const dowY  = lineBottom - metaPad;

    // Draw time with vertical stretch
    ctx.save();
    ctx.textAlign = "left";
    ctx.textBaseline = "alphabetic";
    ctx.shadowColor = "rgba(0,0,0,0.25)";
    ctx.shadowBlur = shadowBlur;
    ctx.shadowOffsetX = 0;
    ctx.shadowOffsetY = Math.round(BASE * 0.001);
    ctx.fillStyle = "#FFFFFF";
    ctx.font = timeTpl(timeFont);

    ctx.save();
    ctx.scale(1, timeScaleY);
    ctx.fillText(timeVal, leftX, timeBaselineY / timeScaleY);
    ctx.restore();
    ctx.restore();

    // Yellow line
    ctx.save();
    ctx.shadowBlur = 0;
    ctx.strokeStyle = "#F2B644";
    ctx.lineWidth = Math.max(2, Math.round(BASE * 0.004));
    ctx.beginPath();
    ctx.moveTo(lineX, lineTop);
    ctx.lineTo(lineX, lineBottom);
    ctx.stroke();
    ctx.restore();

    // Meta text
    ctx.save();
    ctx.textAlign = "left";
    ctx.textBaseline = "alphabetic";
    ctx.shadowColor = "rgba(0,0,0,0.25)";
    ctx.shadowBlur = shadowBlur;
    ctx.shadowOffsetX = 0;
    ctx.shadowOffsetY = Math.round(BASE * 0.001);
    ctx.fillStyle = "#FFFFFF";
    ctx.font = metaTpl(metaFont);

    ctx.fillText(dateText, metaX, dateY);
    ctx.fillText(dowText, metaX, dowY);

    ctx.restore();

    // Address fixed
    ctx.save();
    ctx.textAlign = "left";
    ctx.textBaseline = "bottom";
    ctx.shadowColor = "rgba(0,0,0,0.25)";
    ctx.shadowBlur = shadowBlur;
    ctx.shadowOffsetX = 0;
    ctx.shadowOffsetY = Math.round(BASE * 0.001);
    ctx.fillStyle = "#FFFFFF";
    ctx.font = addrTpl(addrFont);

    ctx.fillText(addr2, leftX, addrBottomY);
    ctx.fillText(addr1, leftX, addrBottomY - addrLineH);

    ctx.restore();
  }

  // Watermark: Time (vàng) + mark (trắng), sub căn giữa theo Timemark
  function drawWatermark(ctx, W, H){
    const BASE = Math.min(W,H);
    const padR = clamp(Math.round(W * 0.02), 10, 40);
    const padB = clamp(Math.round(H * 0.03), 10, 60);

    const timePart = "Time";
    const markPart = "mark";
    const fullText = timePart + markPart;
    const subText = "100% Chân thực";

    let wmFont = clamp(Math.round(BASE * 0.050), 16, 44);
    let subFont = clamp(Math.round(wmFont * 0.55), 10, 24);

    const wmTpl  = (s)=>`700 ${s}px "Roboto Condensed", Roboto, Arial, sans-serif`;
    const subTpl = (s)=>`700 ${s}px "Roboto Condensed", Roboto, Arial, sans-serif`;

    const maxWmWidth = Math.round(W * 0.35);
    wmFont = fitFontToWidth(ctx, fullText, wmTpl, wmFont, 12, maxWmWidth);
    subFont = clamp(Math.round(wmFont * 0.55), 10, 24);

    ctx.save();
    ctx.font = wmTpl(wmFont);
    const wmWidth = ctx.measureText(fullText).width;
    const timeW = ctx.measureText(timePart).width;
    ctx.restore();

    const startX = W - padR - wmWidth;
    const centerX = startX + wmWidth / 2;
    const yBottom = H - padB;

    ctx.save();
    ctx.shadowColor = "rgba(0,0,0,0.22)";
    ctx.shadowBlur = Math.round(BASE * 0.004);
    ctx.shadowOffsetX = 0;
    ctx.shadowOffsetY = Math.round(BASE * 0.001);

    ctx.textBaseline = "bottom";

    // sub: center by Timemark width
    ctx.textAlign = "center";
    ctx.fillStyle = "#E6E6E6";
    ctx.font = subTpl(subFont);
    ctx.fillText(subText, centerX, yBottom);

    // main split color
    const yTop = yBottom - Math.round(subFont * 1.15);
    ctx.textAlign = "left";
    ctx.font = wmTpl(wmFont);

    ctx.fillStyle = "#F2B644";
    ctx.fillText(timePart, startX, yTop);

    ctx.fillStyle = "#FFFFFF";
    ctx.fillText(markPart, startX + timeW, yTop);

    ctx.restore();

    return padR + Math.round(wmWidth) + clamp(Math.round(W*0.03), 12, 40);
  }

  function drawAllOverlay(){
    if(!hasImage) return;

    drawBase();

    const W = cv.width, H = cv.height;
    const timeVal = $("time").value || "05:37";
    const dateText = formatDateDDMMYYYY($("date").value) || "05/01/2026";
    const dowText  = $("dow").value || "Thứ Năm";

    const reservedRight = drawWatermark(ctx, W, H);
    drawLeftCluster(ctx, W, H, reservedRight, timeVal, dateText, dowText);
  }

  function loadImageFromUrl(url){
    img = new Image();
    img.onload = ()=>{
      fitCanvasToImage(img.naturalWidth, img.naturalHeight);
      hasImage = true;

      // Draw immediately
      ctx.drawImage(img,0,0,cv.width,cv.height);
      originalBitmap = ctx.getImageData(0,0,cv.width,cv.height);

      if(!$("date").value){
        const now = new Date();
        const yyyy = now.getFullYear();
        const mm = String(now.getMonth()+1).padStart(2,'0');
        const dd = String(now.getDate()).padStart(2,'0');
        $("date").value = `${yyyy}-${mm}-${dd}`;
      }
      setStatus(`Ảnh: ${cv.width}x${cv.height}`);
      
      // Auto scroll to canvas on mobile
      if(window.innerWidth < 768){
        setTimeout(()=>{ cv.scrollIntoView({behavior:"smooth", block:"center"}); }, 300);
      }
    };
    img.src = url;
  }

  // Events
  $("file").addEventListener("change", (e)=>{
    const f = e.target.files && e.target.files[0];
    if(!f) return;
    const url = URL.createObjectURL(f);
    loadImageFromUrl(url);
  });

  $("render").addEventListener("click", ()=>{
    if(!hasImage) return alert("Bạn chưa chọn ảnh.");
    drawAllOverlay();
    setStatus("Đã ghép overlay");
  });

  $("reset").addEventListener("click", ()=>{
    if(!hasImage) return;
    fitCanvasToImage(img.naturalWidth, img.naturalHeight); // Reset dimensions
    ctx.drawImage(img, 0, 0, cv.width, cv.height); // Redraw original
    originalBitmap = ctx.getImageData(0,0,cv.width,cv.height);
    maskCtx.clearRect(0,0,maskCanvas.width,maskCanvas.height);
    setStatus("Đã reset về ảnh gốc");
  });

  $("download").addEventListener("click", ()=>{
    if(!hasImage) return alert("Bạn chưa chọn ảnh.");
    const a = document.createElement("a");
    a.download = "timemark_export.png";
    a.href = cv.toDataURL("image/png");
    a.click();
  });

  $("toggleMask").addEventListener("click", ()=>{
    maskEnabled = !maskEnabled;
    $("maskBox").style.display = maskEnabled ? "block" : "none";
    $("toggleMask").textContent = maskEnabled ? "🚫 Tắt bút" : "🖌️ Bật bút xóa";
    $("toggleMask").classList.toggle("ok", maskEnabled);
    $("toggleMask").classList.toggle("secondary", !maskEnabled);
  });

  $("clearMask").addEventListener("click", ()=>{
    if(!hasImage) return;
    maskCtx.clearRect(0,0,maskCanvas.width,maskCanvas.height);
    drawBase();
    setStatus("Đã hoàn tác xóa");
  });

  $("brush").addEventListener("input", (e)=>{
    $("brushVal").textContent = e.target.value;
  });

  // Support Touch Events for Mobile Painting
  function getPos(e) {
    const rect = cv.getBoundingClientRect();
    const scaleX = cv.width / rect.width;
    const scaleY = cv.height / rect.height;
    
    let clientX = e.clientX;
    let clientY = e.clientY;
    
    if (e.touches && e.touches.length > 0) {
        clientX = e.touches[0].clientX;
        clientY = e.touches[0].clientY;
    }
    
    return {
        x: (clientX - rect.left) * scaleX,
        y: (clientY - rect.top) * scaleY
    };
  }

  function paint(e){
    if(!maskEnabled || !hasImage || !isPainting) return;
    e.preventDefault(); // Prevent scroll when painting
    const p = getPos(e);
    const size = parseInt($("brush").value,10);
    
    maskCtx.save();
    maskCtx.fillStyle = "rgba(255,255,255,0.95)";
    maskCtx.beginPath();
    maskCtx.arc(p.x,p.y,size/2,0,Math.PI*2);
    maskCtx.fill();
    maskCtx.restore();
    drawBase();
  }

  // Mouse
  cv.addEventListener("mousedown", (e)=>{ isPainting=true; paint(e); });
  window.addEventListener("mouseup", ()=>{ isPainting=false; });
  cv.addEventListener("mousemove", paint);

  // Touch
  cv.addEventListener("touchstart", (e)=>{ isPainting=true; paint(e); }, {passive: false});
  window.addEventListener("touchend", ()=>{ isPainting=false; });
  cv.addEventListener("touchmove", paint, {passive: false});


  // ========== CAMERA ==========
  $("openCamera").addEventListener("click", async ()=>{
    try {
      stream = await navigator.mediaDevices.getUserMedia({ 
        video: { facingMode: "environment" } 
      });
      const vid = $("video");
      vid.srcObject = stream;
      $("cameraModal").classList.add("active");
    } catch(err) {
      alert("Lỗi camera (đảm bảo bạn đang chạy trên HTTPS): " + err.message);
    }
  });

  $("closeCamera").addEventListener("click", ()=>{
    if(stream){
      stream.getTracks().forEach(track => track.stop());
      stream = null;
    }
    $("cameraModal").classList.remove("active");
  });

  $("capture").addEventListener("click", ()=>{
    const video = $("video");
    // Create hi-res canvas matching video source
    const tempCanvas = document.createElement("canvas");
    tempCanvas.width = video.videoWidth;
    tempCanvas.height = video.videoHeight;
    const tempCtx = tempCanvas.getContext("2d");
    
    // Flip if needed? Usually environment cam is fine.
    tempCtx.drawImage(video, 0, 0);
    
    const dataUrl = tempCanvas.toDataURL("image/png");
    loadImageFromUrl(dataUrl);
    
    if(stream){
      stream.getTracks().forEach(track => track.stop());
      stream = null;
    }
    $("cameraModal").classList.remove("active");
  });
</script>
"""


@app.get("/")
@login_required
def index():
    user = current_user()
    return Response(render_page("TimeMark Mobile", INDEX_HTML, user), mimetype="text/html; charset=utf-8")


# =========================
# Admin panel
# =========================
@app.get("/admin")
@admin_required
def admin():
    user = current_user()
    db = get_db()
    users = db.execute("SELECT id, username, role, created_at FROM users ORDER BY role DESC, username ASC").fetchall()

    rows = []
    for u in users:
        rows.append(
            "<tr>"
            f"<td>{u['username']}</td>"
            f"<td>{u['role']}</td>"
            "<td style='white-space:nowrap;'>"
            "<form method='post' action='/admin/delete_user' style='display:inline;' "
            "onsubmit='return confirm(\"Xác nhận xóa?\");'>"
            f"<input type='hidden' name='username' value='{u['username']}'>"
            f"<input type='hidden' name='uid' value='{u['id']}'>"
            "<button class='danger' type='submit' style='padding:6px 10px; font-size:11px;'>Xóa</button>"
            "</form>"
            "</td></tr>"
        )

    table_rows = "\n".join(rows)

    body = (
        "<div class='center' style='max-width:980px;'><div class='card'>"
        "<h2 style='margin:0 0 8px 0; font-size:14px;'>Admin</h2>"
        "<h3 style='margin:14px 0 8px 0; font-size:13px;'>Tạo user mới</h3>"
        "<form method='post' action='/admin/create_user'>"
        "<div class='row'>"
        "<div><label>User</label><input name='username' type='text' required></div>"
        "<div><label>Pass</label><input name='password' type='password' required></div>"
        "</div>"
        "<div class='btns'><button class='ok' type='submit'>Tạo</button>"
        "<a class='badge' href='/'>Quay lại</a></div>"
        "</form>"
        "<h3 style='margin:14px 0 8px 0; font-size:13px;'>Danh sách users</h3>"
        "<table><thead><tr><th>User</th><th>Role</th><th>Act</th></tr></thead>"
        f"<tbody>{table_rows}</tbody></table>"
        "</div></div>"
    )

    return Response(render_page("Admin", body, user), mimetype="text/html; charset=utf-8")


@app.post("/admin/create_user")
@admin_required
def admin_create_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = "user" 
    if not username or not password: return redirect("/admin")
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",(username, generate_password_hash(password), role))
        db.commit()
    except sqlite3.IntegrityError: pass
    return redirect("/admin")

@app.post("/admin/delete_user")
@admin_required
def admin_delete_user():
    username = (request.form.get("username") or "").strip()
    uid = request.form.get("uid")
    if not username: return redirect("/admin")
    db = get_db()
    target = db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    if target and target["role"] == "admin":
        admins = db.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
        if admins <= 1: return redirect("/admin")
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.commit()
    if uid and session.get("uid") == int(uid):
        session.clear()
        return redirect("/login")
    return redirect("/admin")

if __name__ == "__main__":
    # Để chạy trên mạng LAN (điện thoại truy cập được máy tính), dùng host='0.0.0.0'
    app.run(host="0.0.0.0", port=5000, debug=True)