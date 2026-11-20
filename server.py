import os, json, uuid, hashlib, hmac, secrets, datetime, re
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
BASE=Path(__file__).resolve().parent
STAGES=['Component','Bulk Assembly','After Sterilization','Finished Goods']
class Connection:
 def __enter__(self):
  self.c=psycopg.connect(os.environ['DATABASE_URL'],row_factory=dict_row); return self
 def __exit__(self,*args):
  try: return self.c.__exit__(*args)
  finally: self.c.close()
 def execute(self,sql,params=()):
  if sql=='BEGIN IMMEDIATE': return self.c.execute('LOCK TABLE users, inspections IN SHARE ROW EXCLUSIVE MODE')
  return self.c.execute(sql.replace('?', '%s'),params)
 def commit(self): self.c.commit()
def connect(): return Connection()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def password(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),300000).hex()
def init():
 with connect() as c:
  c.execute("""CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','manager','team')), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)))""")
  c.execute("CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, username TEXT REFERENCES users, expires DOUBLE PRECISION)")
  c.execute("CREATE TABLE IF NOT EXISTS inspections(id TEXT PRIMARY KEY, owner TEXT REFERENCES users, version INTEGER NOT NULL, payload TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now())")
  c.execute("CREATE TABLE IF NOT EXISTS audit(id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, at TEXT, actor TEXT, action TEXT, record_id TEXT, before_value TEXT, after_value TEXT, reason TEXT)")
  c.execute("CREATE OR REPLACE FUNCTION reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append only'; END; $$")
  c.execute("DROP TRIGGER IF EXISTS audit_no_change ON audit")
  c.execute("CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE OR TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_change()")
  for user,role,key in [('weni.wiratmadiredja@oneject.co.id','admin','QC_ADMIN_PASSWORD'),('weni.wiratmadiredja@oneject-wego.co.id','admin','QC_ADMIN2_PASSWORD'),('manager','manager','QC_MANAGER_PASSWORD'),('analyst','team','QC_ANALYST_PASSWORD')]:
   p=os.environ.get(key)
   if p and len(p)>=12:
    s=secrets.token_hex(16); result=c.execute('INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,?) ON CONFLICT (username) DO NOTHING',(user,s,password(p,s),role))
    if result.rowcount: c.execute('INSERT INTO audit(at,actor,action,record_id,after_value,reason) VALUES(?,?,?,?,?,?)',(now(),'system','user_bootstrap',user,json.dumps({'username':user,'role':role}),'Administrator provisioning at server startup'))
  for name in ('weni.wiratmadiredja@oneject.co.id','weni.wiratmadiredja@oneject-wego.co.id'):
   if not c.execute('SELECT 1 FROM users WHERE username=?',(name,)).fetchone(): raise SystemExit('Set both QC_ADMIN_PASSWORD and QC_ADMIN2_PASSWORD (at least 12 characters each) before starting.')
LOGIN='''<!doctype html><meta charset=utf-8><title>QC Login</title><style>body{font:16px system-ui;background:#eaf3f6;color:#083b50;display:grid;place-items:center;height:95vh}form{background:white;padding:35px;border-radius:12px;width:300px}input,button{display:block;width:100%;box-sizing:border-box;padding:12px;margin:12px 0}button{background:#087b89;color:white;border:0}</style><form method=post action=/login><h2>ONEJECT WEGO MEDICAL</h2><p>QC Analytical Results Monitoring</p><input name=username placeholder="Username or email" required><input name=password type=password placeholder=Password required><button>Sign in</button></form>'''
class Handler(BaseHTTPRequestHandler):
 def respond(self,status,data,typ='application/json',headers={}):
  b=data.encode() if isinstance(data,str) else json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type',typ); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Length',str(len(b))); [self.send_header(k,v) for k,v in headers.items()]; self.end_headers(); self.wfile.write(b)
 def user(self,c):
  try:
   ck=SimpleCookie(self.headers.get('Cookie','')); t=ck['qc_session'].value
   return c.execute('SELECT u.* FROM sessions s JOIN users u ON u.username=s.username WHERE token=? AND expires>? AND u.active=1',(t,datetime.datetime.now().timestamp())).fetchone()
  except (KeyError,ValueError):return None
 def do_GET(self):
  with connect() as c:
   u=self.user(c)
   if self.path.split('?')[0] in ('/', '/login', '/index.html'):return self.respond(200,(BASE/'index.html').read_text() if u else LOGIN,'text/html; charset=utf-8')
   if self.path=='/health':return self.respond(200,{'status':'ok'})
   if not u:return self.respond(401,{'error':'Sign in required'})
   if self.path=='/api/users':
    if u['role']!='admin':return self.respond(403,{'error':'Admin only'})
    return self.respond(200,[dict(r) for r in c.execute('SELECT username,role,active FROM users ORDER BY username')])
   if self.path=='/api/records':
    rows=c.execute('SELECT * FROM inspections WHERE deleted=0 ORDER BY created_at, id').fetchall(); return self.respond(200,{'role':u['role'],'username':u['username'],'records':[dict(json.loads(r['payload']),version=r['version']) for r in rows]})
   if self.path=='/api/audit' and u['role']!='team':return self.respond(200,[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC')])
   return self.respond(404,{'error':'Not found'})
 def do_POST(self):
  try:
   n=int(self.headers.get('Content-Length','0')); assert 0<n<=2000000
   raw=self.rfile.read(n)
   with connect() as c:
    if self.path=='/login':
     from urllib.parse import parse_qs
     form=parse_qs(raw.decode()); name=form.get('username',[''])[0]; p=form.get('password',[''])[0]; u=c.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
     if not u or not u['active'] or not hmac.compare_digest(u['hash'],password(p,u['salt'])):return self.respond(403,'Invalid login. Return to / and retry.','text/plain')
     t=secrets.token_urlsafe(40); c.execute('INSERT INTO sessions VALUES(?,?,?)',(t,name,datetime.datetime.now().timestamp()+28800)); c.commit(); return self.respond(303,'','text/plain',{'Location':'/','Set-Cookie':f'qc_session={t}; HttpOnly; SameSite=Strict; Path=/'+('; Secure' if os.getenv('QC_HTTPS')=='1' else '')})
    u=self.user(c)
    if not u:return self.respond(401,{'error':'Sign in required'})
    if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.respond(415,{'error':'JSON required'})
    d=json.loads(raw); c.execute('BEGIN IMMEDIATE')
    u=self.user(c)
    if not u:return self.respond(401,{'error':'Sign in required'})
    if self.path=='/api/logout':
     t=SimpleCookie(self.headers.get('Cookie',''))['qc_session'].value; c.execute('DELETE FROM sessions WHERE token=?',(t,)); c.commit(); return self.respond(200,{'ok':True},headers={'Set-Cookie':'qc_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict'})
    if self.path=='/api/users':
     if u['role']!='admin':return self.respond(403,{'error':'Admin only'})
     name=d.get('username',''); action=d.get('action'); reason=str(d.get('reason','')).strip(); role=d.get('role'); pw=d.get('password','')
     if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.@+-]{3,254}',name) or not reason:return self.respond(400,{'error':'Valid username and reason required'})
     before=c.execute('SELECT username,role,active FROM users WHERE username=?',(name,)).fetchone()
     if action=='create':
      if before:return self.respond(409,{'error':'Username already exists'})
      if role not in ('team','manager','admin') or not isinstance(pw,str) or not 12<=len(pw)<=256:return self.respond(400,{'error':'Valid role and password of 12–256 characters required'})
      salt=secrets.token_hex(16); c.execute('INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,?)',(name,salt,password(pw,salt),role))
     elif not before:return self.respond(404,{'error':'User not found'})
     elif action=='update':
      active=d.get('active');
      if role not in ('team','manager','admin') or type(active) is not bool:return self.respond(400,{'error':'Valid role and account status required'})
      if name==u['username'] and (role!='admin' or not active):return self.respond(400,{'error':'You cannot demote or deactivate your own account'})
      c.execute('UPDATE users SET role=?,active=? WHERE username=?',(role,int(active),name)); c.execute('DELETE FROM sessions WHERE username=? AND username<>?',(name,u['username']))
     elif action=='reset':
      if not isinstance(pw,str) or not 12<=len(pw)<=256:return self.respond(400,{'error':'Password of 12–256 characters required'})
      salt=secrets.token_hex(16); c.execute('UPDATE users SET salt=?,hash=? WHERE username=?',(salt,password(pw,salt),name)); c.execute('DELETE FROM sessions WHERE username=?',(name,))
     else:return self.respond(400,{'error':'Unknown action'})
     after=c.execute('SELECT username,role,active FROM users WHERE username=?',(name,)).fetchone(); c.execute('INSERT INTO audit(at,actor,action,record_id,before_value,after_value,reason) VALUES(?,?,?,?,?,?,?)',(now(),u['username'],'user_'+action,name,json.dumps(dict(before)) if before else None,json.dumps(dict(after)),reason)); c.commit(); return self.respond(200,{'ok':True})
    reason=str(d.get('reason','')).strip(); rid=str(d.get('id','')); old=c.execute('SELECT * FROM inspections WHERE id=?',(rid,)).fetchone()
    if self.path not in ('/api/save','/api/delete'):return self.respond(404,{'error':'Not found'})
    if old and (u['role']=='team' or not reason):return self.respond(403,{'error':'Manager or admin and correction reason required'})
    if old and (old['deleted'] or d.get('version')!=old['version']):return self.respond(409,{'error':'Record changed; refresh before retrying'})
    if self.path=='/api/delete':
     if not old:return self.respond(404,{'error':'Record not found'})
     c.execute('UPDATE inspections SET deleted=1,version=version+1 WHERE id=?',(rid,)); after=None; action='soft_delete'
    else:
     r=d['record']; keys=['product','fg','batch','mfg','date','stage','analyst','remarks']; r={**{k:str(r.get(k,''))[:2000] for k in keys},'params':r['params']}; assert r['product'] and r['batch'] and r['date'] and r['stage'] in STAGES; assert 0<len(r['params'])<=500
     for p in r['params']:
      assert all(isinstance(p.get(k),str) for k in ('name','spec','unit','result','assessment')) and p['name'] and p['spec'] and p['assessment'] in ('Pass','Fail','Pending') and (p['assessment']=='Pending' or p['result'].strip())
     r['analyst']=json.loads(old['payload'])['analyst'] if old else u['username']; rid=rid if old else str(uuid.uuid4()); r['id']=rid; after=json.dumps(r,ensure_ascii=False); action='correct' if old else 'create'
     if old:c.execute('UPDATE inspections SET payload=?,version=version+1 WHERE id=?',(after,rid))
     else:c.execute('INSERT INTO inspections(id,owner,version,payload,deleted) VALUES(?,?,1,?,0)',(rid,u['username'],after))
    c.execute('INSERT INTO audit(at,actor,action,record_id,before_value,after_value,reason) VALUES(?,?,?,?,?,?,?)',(now(),u['username'],action,rid,old['payload'] if old else None,after,reason)); c.commit(); return self.respond(200,{'ok':True})
  except (ValueError,KeyError,AssertionError,TypeError):return self.respond(400,{'error':'Invalid input'})
if __name__=='__main__':
 init(); print('QC web: http://localhost:8080',flush=True); ThreadingHTTPServer((os.getenv('QC_HOST','0.0.0.0'),int(os.getenv('PORT','8080'))),Handler).serve_forever()
