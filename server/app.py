"""
WP Monitor — panel central de monitoreo para sitios WordPress.

Dos puertas:
  * /api/v1/report  -> los WordPress envían su reporte con su CÓDIGO (sin Cloudflare Access).
  * todo lo demás   -> panel de administración, protegido por Cloudflare Access
                       (y aquí además se verifica la firma JWT de Access: falla cerrado).
"""
import hashlib
import html
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

import jwt
from flask import Flask, abort, g, jsonify, redirect, request

# ---------------- configuración (variables de entorno) ----------------
DB_PATH = os.environ.get("MONITOR_DB", "/data/monitor.db")
TEAM = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "")        # ej. ilderimmx.cloudflareaccess.com
AUD = os.environ.get("CF_ACCESS_AUD", "")                  # "Application Audience (AUD) Tag" de Access
ADMINS = {x.strip().lower() for x in os.environ.get("ADMIN_EMAILS", "").split(",") if x.strip()}
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "panel.ilderim.mx")
TZ = ZoneInfo(os.environ.get("PANEL_TZ", "America/Mexico_City"))
KEEP = 20                      # reportes guardados por sitio
REPORT_EVERY = 6 * 3600        # cada cuánto debe reportar el plugin (segundos)
MIN_GAP = 60                   # mínimo entre reportes del mismo sitio (anti-abuso)
OK, WARN, BAD = 0, 1, 2

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024
_jwks = jwt.PyJWKClient(f"https://{TEAM}/cdn-cgi/access/certs", cache_keys=True) if TEAM else None

# ---------------- base de datos ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS sites(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  code_hash TEXT UNIQUE NOT NULL,
  code_hint TEXT NOT NULL,
  url TEXT,
  created_at INTEGER NOT NULL,
  last_report_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  mismatch_url TEXT
);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports ON reports(site_id, id);
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.execute("PRAGMA journal_mode=WAL")
    con.close()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


init_db()


def code_hash(code):
    return hashlib.sha256(code.encode()).hexdigest()


def new_code():
    code = "ilm_" + secrets.token_urlsafe(32)
    return code, code_hash(code), code[:8] + "…" + code[-4:]


# ---------------- seguridad del panel ----------------
def admin_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Cf-Access-Jwt-Assertion", "")
        if not (_jwks and AUD and token):
            abort(403)  # sin configuración de Access o sin token: cerrado
        try:
            key = _jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUD,
                                issuer=f"https://{TEAM}")
        except Exception:
            abort(403)
        email = str(claims.get("email", "")).lower()
        if ADMINS and email not in ADMINS:
            abort(403)
        g.user = email
        if request.method == "POST":  # anti-CSRF: el formulario debe venir del propio panel
            origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
            if not origin.startswith(f"https://{PUBLIC_HOST}"):
                abort(403)
        return view(*args, **kwargs)
    return wrapper


# ---------------- API para los WordPress ----------------
@app.post("/api/v1/report")
def api_report():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ilm_"):
        return jsonify(error="no_code"), 401
    con = db()
    site = con.execute("SELECT * FROM sites WHERE code_hash=?",
                       (code_hash(auth[7:].strip()),)).fetchone()
    if site is None:
        return jsonify(error="invalid_code"), 401
    if site["revoked"]:
        return jsonify(error="revoked"), 403
    now = int(time.time())
    if site["last_report_at"] and now - site["last_report_at"] < MIN_GAP:
        return jsonify(error="too_soon"), 429

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="bad_json"), 400
    url = str((data.get("wordpress") or {}).get("site_url") or "").strip().rstrip("/").lower()
    if not url.startswith(("https://", "http://")):
        return jsonify(error="no_site_url"), 400

    if site["url"] is None:                      # primer uso: el código queda amarrado a esta URL
        con.execute("UPDATE sites SET url=?, mismatch_url=NULL WHERE id=?", (url, site["id"]))
    elif site["url"] != url:                     # mismo código desde otro sitio: se rechaza y se avisa
        con.execute("UPDATE sites SET mismatch_url=? WHERE id=?", (url[:200], site["id"]))
        con.commit()
        return jsonify(error="url_mismatch"), 409

    con.execute("INSERT INTO reports(site_id, received_at, data) VALUES(?,?,?)",
                (site["id"], now, json.dumps(data)))
    con.execute("""DELETE FROM reports WHERE site_id=? AND id NOT IN
                   (SELECT id FROM reports WHERE site_id=? ORDER BY id DESC LIMIT ?)""",
                (site["id"], site["id"], KEEP))
    con.execute("UPDATE sites SET last_report_at=? WHERE id=?", (now, site["id"]))
    con.commit()
    return jsonify(ok=True, name=site["name"], next_in=REPORT_EVERY)


# ---------------- reglas de alerta ----------------
def dig(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def num(x):
    try:
        return float(str(x).replace("+", ""))
    except (TypeError, ValueError):
        return None


def parse_dt(s):
    if s in (None, "", False):
        return None
    try:
        if isinstance(s, (int, float)) or str(s).isdigit():
            return datetime.fromtimestamp(int(s), timezone.utc)
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=TZ)


def evaluate(site, data, prev):
    alerts = []
    add = lambda lv, msg: alerts.append((lv, msg))  # noqa: E731
    now = time.time()

    if site["mismatch_url"]:
        add(BAD, f"El código se intentó usar desde otra URL: {site['mismatch_url']}")
    if not site["last_report_at"]:
        add(WARN, "Esperando el primer reporte")
        return alerts
    hours = (now - site["last_report_at"]) / 3600
    if hours > 24:
        add(BAD, f"No reporta desde hace {int(hours)} h")
    elif hours > 12:
        add(WARN, f"No reporta desde hace {int(hours)} h")
    if data is None:
        return alerts

    if dig(data, "wordpress", "needs_update"):
        add(WARN, "WordPress tiene actualización pendiente")
    pu = num(dig(data, "plugins", "needs_update")) or 0
    if pu >= 5:
        add(BAD, f"{int(pu)} plugins por actualizar")
    elif pu > 0:
        add(WARN, f"{int(pu)} plugin(s) por actualizar")

    b = dig(data, "backuply")
    if b is None:
        add(WARN, "Plugin del sitio desactualizado")
    elif not b.get("installed"):
        add(BAD, "Backuply no está instalado")
    else:
        if b.get("status") == "hung":
            add(BAD, "Respaldo atorado")
        if not b.get("scheduled"):
            add(BAD, "Sin respaldos automáticos programados")
        lb = parse_dt(b.get("last_backup"))
        if lb is None:
            add(BAD, "Nunca se ha respaldado")
        else:
            days = (now - lb.timestamp()) / 86400
            if days > 14:
                add(BAD, f"Último respaldo hace {int(days)} días")
            elif days > 8:
                add(WARN, f"Último respaldo hace {int(days)} días")
        lmb = num(b.get("local_mb")) or 0
        if lmb >= 300:
            add(WARN, f"Respaldos locales ocupan {lmb:.0f} MB")

    used = num(dig(data, "disk", "used_percent"))
    if used is not None:
        if used >= 90:
            add(BAD, f"Cuota de disco al {used:.0f}%")
        elif used >= 80:
            add(WARN, f"Cuota de disco al {used:.0f}%")

    if dig(data, "ssl", "enabled") is False:
        add(BAD, "Sin SSL")
    dl = num(dig(data, "ssl", "days_left"))
    if dl is not None:
        if dl < 7:
            add(BAD, f"SSL vence en {int(dl)} días")
        elif dl < 21:
            add(WARN, f"SSL vence en {int(dl)} días")

    if dig(data, "security", "suspicious_activity"):
        add(BAD, "Actividad sospechosa")
    adm, padm = num(dig(data, "security", "admin_users")), num(dig(prev, "security", "admin_users"))
    if adm is not None and padm is not None and adm > padm:
        add(BAD, f"Nuevo administrador ({int(padm)} → {int(adm)})")
    ch = num(dig(data, "security", "users_change_24h"))
    if ch and ch > 0:
        add(WARN, f"{int(ch)} usuario(s) nuevo(s) en 24 h")
    return alerts


# ---------------- vistas HTML ----------------
CSS = """
:root{--bg:#f4f5f7;--card:#fff;--fg:#1d2330;--mut:#6b7280;--line:#e5e7eb;--acc:#2563eb;
--ok:#15803d;--okb:#dcfce7;--warn:#a16207;--warnb:#fef3c7;--bad:#b91c1c;--badb:#fee2e2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#181c25;--fg:#e5e7eb;--mut:#9ca3af;--line:#2a303c;
--acc:#60a5fa;--okb:#14321f;--warnb:#3a2e10;--badb:#3d1717;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
nav{display:flex;gap:18px;align-items:center;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
nav a{color:var(--fg);text-decoration:none;font-weight:600}nav a.on{color:var(--acc)}nav .u{margin-left:auto;color:var(--mut);font-size:13px}
main{max-width:1200px;margin:0 auto;padding:20px}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px}
.sum{display:flex;gap:10px;margin:12px 0 18px;flex-wrap:wrap}
.pill{padding:3px 11px;border-radius:999px;font-weight:600;font-size:13px;white-space:nowrap}
.ok{background:var(--okb);color:var(--ok)}.warn{background:var(--warnb);color:var(--warn)}.bad{background:var(--badb);color:var(--bad)}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;border-top:4px solid var(--line)}
.l0{border-top-color:var(--ok)}.l1{border-top-color:var(--warn)}.l2{border-top-color:var(--bad)}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px}.top b{font-size:16px}
.url{font-size:13px;color:var(--mut);word-break:break-all}.url a{color:inherit}
.m{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0}
.m div{background:var(--bg);border-radius:8px;padding:6px 8px}.m b{display:block;font-size:14px}
.m span{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.03em}
ul.al{margin:8px 0;padding-left:18px;font-size:14px}li.l2{color:var(--bad)}li.l1{color:var(--warn)}
details{font-size:13px;margin-top:6px}summary{cursor:pointer;color:var(--mut)}.foot{font-size:12px;color:var(--mut);margin-top:8px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
th{font-size:12px;color:var(--mut);text-transform:uppercase}.tw{overflow-x:auto}
form.inl{display:inline}button,.btn{font:inherit;font-size:13px;padding:6px 12px;border-radius:8px;border:1px solid var(--line);
background:var(--card);color:var(--fg);cursor:pointer}button.pri{background:var(--acc);border-color:var(--acc);color:#fff}
button.dan{color:var(--bad)}input[type=text]{font:inherit;padding:7px 10px;border-radius:8px;border:1px solid var(--line);
background:var(--card);color:var(--fg);min-width:260px}.add{display:flex;gap:8px;margin:14px 0 20px;flex-wrap:wrap}
.code{background:var(--card);border:2px dashed var(--acc);border-radius:12px;padding:16px;margin:0 0 20px}
.code code{display:block;font-size:15px;word-break:break-all;background:var(--bg);padding:10px;border-radius:8px;margin:8px 0;user-select:all}
"""
LABEL = {OK: ("ok", "Todo bien"), WARN: ("warn", "Revisar"), BAD: ("bad", "Crítico")}


def e(x):
    return html.escape("—" if x in (None, "") else str(x))


def local(ts, fmt="%d/%m %H:%M"):
    dt = parse_dt(ts)
    return dt.astimezone(TZ).strftime(fmt) if dt else "—"


def page(title, body, active):
    nav = "".join(f'<a href="{href}" class="{"on" if key == active else ""}">{label}</a>'
                  for key, href, label in (("panel", "/", "Panel"), ("sitios", "/sitios", "Sitios")))
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)} · WP Monitor</title>
<style>{CSS}</style></head><body><nav><a href="/"><b>WP Monitor</b></a>{nav}
<span class="u">{e(getattr(g, "user", ""))}</span></nav><main>{body}</main></body></html>"""


def latest_two(con, site_id):
    rows = con.execute("SELECT data FROM reports WHERE site_id=? ORDER BY id DESC LIMIT 2",
                       (site_id,)).fetchall()
    data = json.loads(rows[0]["data"]) if rows else None
    prev = json.loads(rows[1]["data"]) if len(rows) > 1 else None
    return data, prev


def site_card(site, data, alerts, level):
    d = data or {}
    cls, label = LABEL[level]
    b = d.get("backuply") or {}
    used = num(dig(d, "disk", "used_percent"))
    tipo = {True: " (auto)", False: " (manual)"}.get(b.get("last_auto"), "")
    pend = [p for p in (dig(d, "plugins", "lista") or []) if isinstance(p, dict) and p.get("needs_update")]
    out = [f'<div class="card l{level}"><div class="top"><b>{e(site["name"])}</b>'
           f'<span class="pill {cls}">{label}</span></div>']
    out.append(f'<div class="url"><a href="{e(site["url"])}/wp-admin/" target="_blank" rel="noopener">'
               f'{e(site["url"])}</a></div>' if site["url"] else '<div class="url">Sin conectar</div>')
    if alerts:
        out.append('<ul class="al">' + "".join(f'<li class="l{lv}">{e(m)}</li>'
                                              for lv, m in sorted(alerts, reverse=True)) + "</ul>")
    if data:
        metrics = [
            ("WordPress", e(dig(d, "wordpress", "version")) + (" ↑" if dig(d, "wordpress", "needs_update") else "")),
            ("Plugins pend.", f'{e(dig(d, "plugins", "needs_update"))} / {e(dig(d, "plugins", "total"))}'),
            ("Último respaldo", e(local(b.get("last_backup"))) + tipo),
            ("Programado", ("Sí · " + e(local(b.get("next_run")))) if b.get("scheduled") else "No"),
            ("Cuota disco", f"{used:.0f}%" if used is not None else "—"),
            ("SSL", f'{e(dig(d, "ssl", "days_left"))} días'),
            ("Admins", e(dig(d, "security", "admin_users"))),
            ("Usuarios", e(dig(d, "security", "users_total"))),
            ("Spam", e(dig(d, "security", "comments_spam"))),
        ]
        out.append('<div class="m">' + "".join(f"<div><span>{k}</span><b>{v}</b></div>" for k, v in metrics) + "</div>")
    if pend:
        out.append(f"<details><summary>Plugins por actualizar ({len(pend)})</summary><ul>" + "".join(
            f"<li>{e(p.get('name'))} <span class='sub'>v{e(p.get('version'))}</span></li>" for p in pend) + "</ul></details>")
    bk = b.get("backups") or []
    if bk:
        out.append("<details><summary>Respaldos recientes</summary><ul>" + "".join(
            f"<li>{e(local(x.get('date')))} — {e(x.get('size_mb'))} MB · {'auto' if x.get('auto') else 'manual'}"
            f" · {e(x.get('location'))}</li>" for x in bk if isinstance(x, dict)) + "</ul></details>")
    out.append(f'<div class="foot">Último reporte: {e(local(site["last_report_at"]))}</div></div>')
    return "".join(out)


@app.get("/")
@admin_only
def dashboard():
    con = db()
    cards = []
    for site in con.execute("SELECT * FROM sites WHERE revoked=0 ORDER BY name"):
        data, prev = latest_two(con, site["id"])
        alerts = evaluate(site, data, prev)
        level = max((a[0] for a in alerts), default=OK)
        cards.append((level, site["name"].lower(), site_card(site, data, alerts, level)))
    cards.sort(key=lambda c: (-c[0], c[1]))
    n = {lv: sum(1 for c in cards if c[0] == lv) for lv in (OK, WARN, BAD)}
    body = f"""<h1>Panel</h1><div class="sub">{len(cards)} sitios · actualizado {datetime.now(TZ):%d/%m/%Y %H:%M}</div>
<div class="sum"><span class="pill bad">{n[BAD]} críticos</span><span class="pill warn">{n[WARN]} por revisar</span>
<span class="pill ok">{n[OK]} bien</span></div>
<div class="grid">{''.join(c[2] for c in cards) or '<p>No hay sitios. Agrega uno en <a href="/sitios">Sitios</a>.</p>'}</div>
<script>setTimeout(()=>location.reload(),600000)</script>"""
    return page("Panel", body, "panel")


def sites_page(new=None):
    con = db()
    rows = []
    for s in con.execute("SELECT * FROM sites ORDER BY name"):
        if s["revoked"]:
            estado = '<span class="pill warn">Revocado</span>'
        elif s["mismatch_url"]:
            estado = '<span class="pill bad">Uso indebido</span>'
        elif s["url"]:
            estado = '<span class="pill ok">Conectado</span>'
        else:
            estado = '<span class="pill warn">Pendiente</span>'
        sid = s["id"]
        acciones = (
            f'<form class="inl" method="post" action="/sitios/{sid}/regenerar" '
            f'onsubmit="return confirm(\'¿Generar un código nuevo? El anterior deja de funcionar.\')"><button>Regenerar</button></form> '
            f'<form class="inl" method="post" action="/sitios/{sid}/revocar"><button>{"Reactivar" if s["revoked"] else "Revocar"}</button></form> '
            + (f'<form class="inl" method="post" action="/sitios/{sid}/liberar" '
               f'onsubmit="return confirm(\'¿Liberar la URL? El próximo sitio que use el código quedará amarrado.\')"><button>Liberar URL</button></form> '
               if s["url"] else "")
            + f'<form class="inl" method="post" action="/sitios/{sid}/eliminar" '
            f'onsubmit="return confirm(\'¿Eliminar {e(s["name"])} y todo su historial?\')"><button class="dan">Eliminar</button></form>')
        rows.append(f"<tr><td><b>{e(s['name'])}</b></td><td>{e(s['url'] or 'Sin conectar')}</td>"
                    f"<td><code>{e(s['code_hint'])}</code></td><td>{e(local(s['last_report_at']))}</td>"
                    f"<td>{estado}</td><td>{acciones}</td></tr>")
    box = ""
    if new:
        name, code = new
        box = (f'<div class="code"><b>Código para {e(name)}</b> — cópialo ahora, no se vuelve a mostrar.'
               f'<code>{e(code)}</code><div class="sub">En el WordPress: <b>Ajustes → WP Monitor</b> → '
               f'Servidor: <b>{e(PUBLIC_HOST)}</b> · Código: el de arriba → <b>Conectar</b>.</div></div>')
    body = f"""<h1>Sitios</h1><div class="sub">Cada sitio tiene su propio código. Se guarda solo su huella, nunca el código.</div>
<form class="add" method="post" action="/sitios"><input type="text" name="name" maxlength="80" required
placeholder="Nombre del cliente o sitio"><button class="pri">Agregar y generar código</button></form>{box}
<div class="tw"><table><tr><th>Nombre</th><th>URL</th><th>Código</th><th>Último reporte</th><th>Estado</th><th></th></tr>
{''.join(rows) or '<tr><td colspan="6">Todavía no hay sitios.</td></tr>'}</table></div>"""
    return page("Sitios", body, "sitios")


@app.get("/sitios")
@admin_only
def sitios():
    return sites_page()


@app.post("/sitios")
@admin_only
def sitios_add():
    name = (request.form.get("name") or "").strip()[:80]
    if not name:
        return redirect("/sitios", 303)
    code, chash, hint = new_code()
    con = db()
    con.execute("INSERT INTO sites(name, code_hash, code_hint, created_at) VALUES(?,?,?,?)",
                (name, chash, hint, int(time.time())))
    con.commit()
    return sites_page(new=(name, code))


@app.post("/sitios/<int:sid>/regenerar")
@admin_only
def sitios_regen(sid):
    con = db()
    site = con.execute("SELECT name FROM sites WHERE id=?", (sid,)).fetchone()
    if site is None:
        abort(404)
    code, chash, hint = new_code()
    con.execute("UPDATE sites SET code_hash=?, code_hint=?, mismatch_url=NULL WHERE id=?", (chash, hint, sid))
    con.commit()
    return sites_page(new=(site["name"], code))


@app.post("/sitios/<int:sid>/revocar")
@admin_only
def sitios_revoke(sid):
    con = db()
    con.execute("UPDATE sites SET revoked = 1 - revoked WHERE id=?", (sid,))
    con.commit()
    return redirect("/sitios", 303)


@app.post("/sitios/<int:sid>/liberar")
@admin_only
def sitios_release(sid):
    con = db()
    con.execute("UPDATE sites SET url=NULL, mismatch_url=NULL WHERE id=?", (sid,))
    con.commit()
    return redirect("/sitios", 303)


@app.post("/sitios/<int:sid>/eliminar")
@admin_only
def sitios_delete(sid):
    con = db()
    con.execute("DELETE FROM sites WHERE id=?", (sid,))
    con.commit()
    return redirect("/sitios", 303)


@app.errorhandler(403)
def _forbidden(_e):
    return "Acceso denegado.", 403
