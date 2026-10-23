import os, hashlib, secrets, base64
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps
from io import BytesIO

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import inspect, or_
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

load_dotenv()
BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR', BASE / 'private_files')).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.config.update(SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', f"sqlite:///{BASE / 'app.db'}"), SQLALCHEMY_TRACK_MODIFICATIONS=False, SECRET_KEY=os.getenv('FLASK_SECRET_KEY', 'dev-only-change-this'), MAX_CONTENT_LENGTH=20*1024*1024)
CORS(app, origins=os.getenv('FRONTEND_ORIGIN','http://localhost:5173'))
db, bcrypt = SQLAlchemy(app), Bcrypt(app)
ALLOWED={'pdf','docx','png','jpg','jpeg','txt'}

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(120),nullable=False); email=db.Column(db.String(255),unique=True,nullable=False,index=True); password_hash=db.Column(db.String(255),nullable=False); token_hash=db.Column(db.String(64),index=True); email_verified=db.Column(db.Boolean,nullable=False,default=True); role=db.Column(db.String(20),nullable=False,default='user')
class Document(db.Model):
    id=db.Column(db.Integer,primary_key=True); owner_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,index=True); filename=db.Column(db.String(255),nullable=False); blob_name=db.Column(db.String(64),nullable=False,unique=True); sha256=db.Column(db.String(64),nullable=False); size=db.Column(db.Integer,nullable=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
class Share(db.Model):
    id=db.Column(db.Integer,primary_key=True); document_id=db.Column(db.Integer,db.ForeignKey('document.id'),nullable=False,index=True); recipient_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,index=True); permission=db.Column(db.String(12),nullable=False,default='view'); expires_at=db.Column(db.DateTime); revoked_at=db.Column(db.DateTime); download_limit=db.Column(db.Integer); download_count=db.Column(db.Integer,nullable=False,default=0); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
    __table_args__=(db.UniqueConstraint('document_id','recipient_id'),)
class Audit(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id')); document_id=db.Column(db.Integer,db.ForeignKey('document.id')); action=db.Column(db.String(32),nullable=False); result=db.Column(db.String(16),nullable=False); detail=db.Column(db.String(255)); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
class ActionToken(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,index=True); token_hash=db.Column(db.String(64),unique=True,nullable=False,index=True); purpose=db.Column(db.String(24),nullable=False); expires_at=db.Column(db.DateTime,nullable=False); consumed_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
class Notification(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False,index=True); message=db.Column(db.String(255),nullable=False); is_read=db.Column(db.Boolean,nullable=False,default=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
class PublicLink(db.Model):
    id=db.Column(db.Integer,primary_key=True); document_id=db.Column(db.Integer,db.ForeignKey('document.id'),nullable=False,index=True); token_hash=db.Column(db.String(64),unique=True,nullable=False,index=True); permission=db.Column(db.String(12),nullable=False,default='view'); expires_at=db.Column(db.DateTime); download_limit=db.Column(db.Integer); download_count=db.Column(db.Integer,nullable=False,default=0); revoked_at=db.Column(db.DateTime); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)

def migrate_schema():
    """Add columns to existing installs without deleting documents or accounts."""
    quote=db.engine.dialect.identifier_preparer.quote
    additions={
        User.__tablename__:{'email_verified':'BOOLEAN NOT NULL DEFAULT TRUE','role':"VARCHAR(20) NOT NULL DEFAULT 'user'"},
        Share.__tablename__:{'download_limit':'INTEGER','download_count':'INTEGER NOT NULL DEFAULT 0'},
    }
    with db.engine.begin() as conn:
        inspector=inspect(conn); tables=set(inspector.get_table_names())
        for table,columns in additions.items():
            if table not in tables: continue
            existing={column['name'] for column in inspector.get_columns(table)}
            for name,ddl in columns.items():
                if name not in existing:
                    conn.exec_driver_sql(f'ALTER TABLE {quote(table)} ADD COLUMN {quote(name)} {ddl}')

with app.app_context():
    db.create_all()
    migrate_schema()

def log(action,result='success',doc=None,detail=None,uid=None):
    db.session.add(Audit(user_id=uid if uid is not None else getattr(g,'user_id',None),document_id=doc.id if doc else None,action=action,result=result,detail=detail)); db.session.commit()
    if result=='denied' and doc:
        since=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(minutes=10)
        failures=Audit.query.filter_by(document_id=doc.id,action=action,result='denied').filter(Audit.created_at>=since).count()
        if failures==5:notify(doc.owner_id,f'Multiple denied access attempts for {doc.filename} in the last 10 minutes.')
def notify(uid,message):
    db.session.add(Notification(user_id=uid,message=message)); db.session.commit()
def issue_action_token(user,purpose,minutes):
    raw=secrets.token_urlsafe(32); expires=datetime.now(timezone.utc).replace(tzinfo=None)+timedelta(minutes=minutes)
    db.session.add(ActionToken(user_id=user.id,token_hash=hashlib.sha256(raw.encode()).hexdigest(),purpose=purpose,expires_at=expires)); db.session.commit()
    return raw
def consume_action_token(raw,purpose):
    if not raw:return None
    item=ActionToken.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest(),purpose=purpose,consumed_at=None).first()
    now=datetime.now(timezone.utc).replace(tzinfo=None)
    if not item or item.expires_at<=now:return None
    item.consumed_at=now; db.session.commit(); return User.query.get(item.user_id)
def dev_action_url(action,raw):
    return f"{os.getenv('FRONTEND_URL','http://localhost:5173')}/?{action}={raw}"
def auth(f):
    @wraps(f)
    def wrapped(*args,**kwargs):
        raw=request.headers.get('Authorization',''); token=raw[7:] if raw.startswith('Bearer ') else ''
        user=User.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first() if token else None
        if not user:return jsonify(error='Authentication required'),401
        g.user_id=user.id; return f(*args,**kwargs)
    return wrapped
def encryption_key():
    value=os.getenv('FILE_ENCRYPTION_KEY')
    if not value:raise RuntimeError('FILE_ENCRYPTION_KEY must be configured (32 bytes, base64 encoded)')
    decoded=base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    if len(decoded)!=32:raise RuntimeError('FILE_ENCRYPTION_KEY must decode to 32 bytes')
    return decoded
def metadata(doc):
    owner=User.query.get(doc.owner_id)
    return {'id':doc.id,'filename':doc.filename,'size':doc.size,'sha256':doc.sha256,'owner':owner.name if owner else '', 'created_at':doc.created_at.isoformat()}

@app.get('/api/health')
def health():return jsonify(status='ok')
@app.post('/api/register')
def register():
    data=request.get_json(silent=True) or {}; name=(data.get('name') or '').strip(); email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
    if not name or len(name)>120 or '@' not in email or len(password)<10:return jsonify(error='Enter a name, valid email, and password with at least 10 characters'),400
    if User.query.filter_by(email=email).first():return jsonify(error='An account with that email already exists'),409
    user=User(name=name,email=email,password_hash=bcrypt.generate_password_hash(password).decode(),email_verified=False); db.session.add(user); db.session.commit(); log('register',uid=user.id)
    raw=issue_action_token(user,'verify_email',60*24)
    response={'message':'Account created. Verify your email before signing in.'}
    if os.getenv('APP_ENV','development')=='development':response['verification_token']=raw
    return jsonify(response),201
@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {}
    email=data.get('email') or ''
    password=data.get('password') or ''
    if not isinstance(email,str) or not isinstance(password,str):
        return jsonify(error='Enter a valid email and password'),400
    email=email.strip().lower()
    user=User.query.filter_by(email=email).first()
    try:
        password_matches=bool(user and len(password.encode('utf-8'))<=72 and bcrypt.check_password_hash(user.password_hash,password))
    except (TypeError, ValueError):
        # A malformed legacy hash or a password rejected by bcrypt must not turn
        # an ordinary sign-in attempt into an unhandled HTTP 500.
        password_matches=False
    if not password_matches:
        log('login','denied',detail='Invalid credentials',uid=user.id if user else None); return jsonify(error='Email or password is incorrect'),401
    if not user.email_verified:return jsonify(error='Verify your email before signing in. Use “Resend verification link” below to get a new link.'),403
    token=secrets.token_urlsafe(36); user.token_hash=hashlib.sha256(token.encode()).hexdigest(); db.session.commit(); log('login',uid=user.id)
    return jsonify(token=token,user={'id':user.id,'name':user.name,'email':user.email})

@app.post('/api/verify-email')
def verify_email():
    data=request.get_json(silent=True) or {}; user=consume_action_token(data.get('token'),'verify_email')
    if not user:return jsonify(error='Verification link is invalid or expired'),400
    user.email_verified=True; db.session.commit(); log('email_verified',uid=user.id); return jsonify(message='Email verified. You can sign in now.')

@app.post('/api/verification-link/request')
def request_verification_link():
    data=request.get_json(silent=True) or {}; email=(data.get('email') or '').strip().lower()
    user=User.query.filter_by(email=email).first() if email else None
    response={'message':'If that account needs verification, a new link has been created.'}
    if user and not user.email_verified:
        raw=issue_action_token(user,'verify_email',60*24)
        if os.getenv('APP_ENV','development')=='development':response['verification_token']=raw
    return jsonify(response)

@app.post('/api/password-reset/request')
def request_password_reset():
    data=request.get_json(silent=True) or {}; email=(data.get('email') or '').strip().lower(); user=User.query.filter_by(email=email).first()
    response={'message':'If that account exists, a reset link has been created.'}
    if user:
        raw=issue_action_token(user,'password_reset',30)
        if os.getenv('APP_ENV','development')=='development':response['reset_token']=raw
    return jsonify(response)

@app.post('/api/password-reset/complete')
def complete_password_reset():
    data=request.get_json(silent=True) or {}; password=data.get('password') or ''
    if len(password)<10:return jsonify(error='Password must contain at least 10 characters'),400
    user=consume_action_token(data.get('token'),'password_reset')
    if not user:return jsonify(error='Reset link is invalid or expired'),400
    user.password_hash=bcrypt.generate_password_hash(password).decode(); user.token_hash=None; db.session.commit(); log('password_reset',uid=user.id)
    return jsonify(message='Password reset. You can sign in with your new password.')
@app.post('/api/logout')
@auth
def logout():
    user=User.query.get(g.user_id); user.token_hash=None; db.session.commit(); log('logout'); return jsonify(message='Signed out')
@app.get('/api/me')
@auth
def me():
    user=User.query.get(g.user_id); return jsonify(id=user.id,name=user.name,email=user.email)
@app.get('/api/users')
@auth
def users():
    q=(request.args.get('q') or '').strip().lower()
    return jsonify([{'id':u.id,'name':u.name,'email':u.email} for u in User.query.filter(User.id!=g.user_id,User.email.contains(q)).limit(20).all()])

def authorized(doc_id,download=False):
    doc=Document.query.get_or_404(doc_id)
    if doc.owner_id==g.user_id:return doc
    share=Share.query.filter_by(document_id=doc.id,recipient_id=g.user_id,revoked_at=None).first(); now=datetime.now(timezone.utc)
    within_limit=not download or (share and (share.download_limit is None or share.download_count<share.download_limit))
    if share and within_limit and (not share.expires_at or share.expires_at.replace(tzinfo=timezone.utc)>now) and (not download or share.permission=='download'):return doc
    log('access','denied',doc,'Permission missing, expired, or revoked'); return None

@app.post('/api/documents')
@auth
def upload():
    f=request.files.get('file')
    if not f:return jsonify(error='Choose a file'),400
    filename=secure_filename(f.filename or ''); ext=filename.rsplit('.',1)[-1].lower() if '.' in filename else ''
    if not filename or ext not in ALLOWED:return jsonify(error='Allowed file types: PDF, DOCX, PNG, JPG, JPEG, TXT'),400
    raw=f.read()
    if not raw:return jsonify(error='The file is empty'),400
    try:
        key=encryption_key()
    except (RuntimeError, ValueError):
        return jsonify(error='File encryption is not configured correctly. Set FILE_ENCRYPTION_KEY to a valid 32-byte URL-safe base64 key and restart the backend.'),503
    digest=hashlib.sha256(raw).hexdigest(); blob=secrets.token_hex(24); nonce=secrets.token_bytes(12)
    (DATA_DIR/blob).write_bytes(nonce+AESGCM(key).encrypt(nonce,raw,None))
    doc=Document(owner_id=g.user_id,filename=filename,blob_name=blob,sha256=digest,size=len(raw)); db.session.add(doc); db.session.commit(); log('upload',doc=doc)
    return jsonify(metadata(doc)),201

@app.put('/api/documents/<int:doc_id>')
@auth
def replace_document(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); f=request.files.get('file')
    if not f:return jsonify(error='Choose a replacement file'),400
    filename=secure_filename(f.filename or ''); ext=filename.rsplit('.',1)[-1].lower() if '.' in filename else ''
    if not filename or ext not in ALLOWED:return jsonify(error='Allowed file types: PDF, DOCX, PNG, JPG, JPEG, TXT'),400
    raw=f.read()
    if not raw:return jsonify(error='The file is empty'),400
    digest=hashlib.sha256(raw).hexdigest(); blob=secrets.token_hex(24); nonce=secrets.token_bytes(12)
    try:
        (DATA_DIR/blob).write_bytes(nonce+AESGCM(encryption_key()).encrypt(nonce,raw,None))
        old_blob=doc.blob_name; doc.blob_name=blob; doc.filename=filename; doc.sha256=digest; doc.size=len(raw); db.session.commit()
    except Exception:
        db.session.rollback(); (DATA_DIR/blob).unlink(missing_ok=True); raise
    (DATA_DIR/old_blob).unlink(missing_ok=True); log('replace',doc=doc); return jsonify(metadata(doc))

@app.get('/api/documents')
@auth
def documents():
    own=Document.query.filter_by(owner_id=g.user_id).order_by(Document.created_at.desc()).all(); shares=Share.query.filter_by(recipient_id=g.user_id,revoked_at=None).all(); shared=[]
    for s in shares:
        if s.expires_at and s.expires_at.replace(tzinfo=timezone.utc)<=datetime.now(timezone.utc):continue
        d=Document.query.get(s.document_id)
        if d:item=metadata(d); item.update(permission=s.permission,shared=True); shared.append(item)
    return jsonify(owned=[metadata(d) for d in own],shared=shared)

@app.get('/api/documents/<int:doc_id>/download')
@auth
def download(doc_id):
    doc=authorized(doc_id,download=True)
    if not doc:return jsonify(error='You do not have download access'),403
    try:
        payload=(DATA_DIR/doc.blob_name).read_bytes(); raw=AESGCM(encryption_key()).decrypt(payload[:12],payload[12:],None)
    except Exception:
        log('download','error',doc,'Decryption or storage error'); return jsonify(error='Unable to decrypt document'),500
    if hashlib.sha256(raw).hexdigest()!=doc.sha256:log('integrity_check','failed',doc); return jsonify(error='Integrity verification failed'),409
    if doc.owner_id!=g.user_id:
        share=Share.query.filter_by(document_id=doc.id,recipient_id=g.user_id,revoked_at=None).first()
        if share:
            now=datetime.now(timezone.utc).replace(tzinfo=None)
            q=Share.query.filter_by(id=share.id,revoked_at=None,permission='download').filter(or_(Share.expires_at.is_(None),Share.expires_at>now))
            if share.download_limit is not None:q=q.filter(Share.download_count<share.download_limit)
            if q.update({Share.download_count:Share.download_count+1},synchronize_session=False)!=1:
                db.session.rollback(); return jsonify(error='Download permission was revoked, expired, or reached its limit'),403
            db.session.commit()
    log('download',doc=doc); return send_file(BytesIO(raw),download_name=doc.filename,as_attachment=True)

@app.get('/api/documents/<int:doc_id>/preview')
@auth
def preview(doc_id):
    doc=authorized(doc_id)
    if not doc:return jsonify(error='You do not have view access'),403
    ext=doc.filename.rsplit('.',1)[-1].lower()
    if ext not in {'pdf','png','jpg','jpeg','txt'}:return jsonify(error='Inline preview is available for PDF, image, and text files. Download this file if your permission allows it.'),415
    try:
        payload=(DATA_DIR/doc.blob_name).read_bytes(); raw=AESGCM(encryption_key()).decrypt(payload[:12],payload[12:],None)
    except Exception:
        log('preview','error',doc,'Decryption or storage error'); return jsonify(error='Unable to decrypt document'),500
    if hashlib.sha256(raw).hexdigest()!=doc.sha256:log('integrity_check','failed',doc); return jsonify(error='Integrity verification failed'),409
    mime={'pdf':'application/pdf','png':'image/png','jpg':'image/jpeg','jpeg':'image/jpeg','txt':'text/plain'}[ext]
    log('view',doc=doc); return send_file(BytesIO(raw),mimetype=mime,download_name=doc.filename,as_attachment=False)

@app.get('/api/documents/<int:doc_id>/shares')
@auth
def list_shares(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); result=[]
    for s in Share.query.filter_by(document_id=doc.id).all():
        recipient=User.query.get(s.recipient_id)
        result.append({'recipient_id':s.recipient_id,'name':recipient.name if recipient else '', 'email':recipient.email if recipient else '', 'permission':s.permission,'expires_at':s.expires_at.isoformat() if s.expires_at else None,'download_limit':s.download_limit,'download_count':s.download_count,'revoked':s.revoked_at is not None})
    return jsonify(result)

@app.post('/api/documents/<int:doc_id>/share')
@auth
def share(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); data=request.get_json(silent=True) or {}; recipient=User.query.filter_by(email=(data.get('email') or '').strip().lower()).first(); perm=data.get('permission','view')
    if not recipient or recipient.id==g.user_id:return jsonify(error='Choose an existing recipient account'),400
    if perm not in {'view','download'}:return jsonify(error='Permission must be view or download'),400
    download_limit=data.get('download_limit')
    if download_limit in ('',None):download_limit=None
    else:
        try:download_limit=int(download_limit)
        except (TypeError,ValueError):return jsonify(error='Download limit must be a positive integer'),400
        if download_limit<1:return jsonify(error='Download limit must be a positive integer'),400
        if perm!='download':return jsonify(error='Download limits require download permission'),400
    expires=None
    if data.get('expires_at'):
        try:expires=datetime.fromisoformat(data['expires_at'].replace('Z','+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:return jsonify(error='Invalid expiry date'),400
        if expires<=datetime.now(timezone.utc).replace(tzinfo=None):return jsonify(error='Expiry must be in the future'),400
    s=Share.query.filter_by(document_id=doc.id,recipient_id=recipient.id).first()
    if s:s.permission=perm; s.expires_at=expires; s.download_limit=download_limit; s.download_count=0; s.revoked_at=None
    else:s=Share(document_id=doc.id,recipient_id=recipient.id,permission=perm,expires_at=expires,download_limit=download_limit); db.session.add(s)
    db.session.commit(); notify(recipient.id,f'{User.query.get(g.user_id).name} shared {doc.filename} with you.'); log('share',doc=doc,detail=f'Shared with {recipient.email} ({perm})'); return jsonify(message='Access granted')

@app.delete('/api/documents/<int:doc_id>/share/<int:recipient_id>')
@auth
def revoke(doc_id,recipient_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); s=Share.query.filter_by(document_id=doc.id,recipient_id=recipient_id,revoked_at=None).first_or_404(); s.revoked_at=datetime.now(timezone.utc).replace(tzinfo=None); db.session.commit(); log('revoke',doc=doc,detail=f'Recipient {recipient_id}'); return jsonify(message='Access revoked')

@app.delete('/api/documents/<int:doc_id>')
@auth
def delete_doc(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); path=DATA_DIR/doc.blob_name
    if path.exists():path.unlink()
    Share.query.filter_by(document_id=doc.id).delete(); PublicLink.query.filter_by(document_id=doc.id).delete(); Audit.query.filter_by(document_id=doc.id).delete(); db.session.delete(doc); db.session.commit(); log('delete',detail=f'Document {doc.id} deleted'); return jsonify(message='Document deleted')

@app.get('/api/activity')
@auth
def activity():
    owned_ids=db.session.query(Document.id).filter_by(owner_id=g.user_id)
    rows=Audit.query.filter((Audit.user_id==g.user_id)|(Audit.document_id.in_(owned_ids))).order_by(Audit.created_at.desc()).limit(100).all(); result=[]
    for a in rows:
        doc=Document.query.get(a.document_id) if a.document_id else None
        result.append({'id':a.id,'action':a.action,'result':a.result,'detail':a.detail,'created_at':a.created_at.isoformat(),'filename':doc.filename if doc else None})
    return jsonify(result)

@app.get('/api/dashboard')
@auth
def dashboard():
    own_count=Document.query.filter_by(owner_id=g.user_id).count()
    share_count=Share.query.join(Document,Document.id==Share.document_id).filter(Document.owner_id==g.user_id,Share.revoked_at.is_(None)).count()
    since=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(days=1)
    failed=Audit.query.join(Document,Document.id==Audit.document_id).filter(Document.owner_id==g.user_id,Audit.result=='denied',Audit.created_at>=since).count()
    return jsonify(documents=own_count,active_shares=share_count,security_alerts=failed)

@app.get('/api/notifications')
@auth
def notifications():
    rows=Notification.query.filter_by(user_id=g.user_id).order_by(Notification.created_at.desc()).limit(50).all()
    return jsonify([{'id':n.id,'message':n.message,'is_read':n.is_read,'created_at':n.created_at.isoformat()} for n in rows])

@app.post('/api/notifications/<int:notification_id>/read')
@auth
def mark_notification_read(notification_id):
    item=Notification.query.filter_by(id=notification_id,user_id=g.user_id).first_or_404(); item.is_read=True; db.session.commit(); return jsonify(message='Notification marked read')

def active_public_link(raw):
    if not raw:return None
    link=PublicLink.query.filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest(),revoked_at=None).first()
    now=datetime.now(timezone.utc).replace(tzinfo=None)
    if not link or (link.expires_at and link.expires_at<=now) or (link.download_limit is not None and link.download_count>=link.download_limit):return None
    return link

@app.post('/api/documents/<int:doc_id>/links')
@auth
def create_public_link(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); data=request.get_json(silent=True) or {}; permission=data.get('permission','view')
    if permission not in {'view','download'}:return jsonify(error='Permission must be view or download'),400
    limit=data.get('download_limit')
    if limit in ('',None):limit=None
    else:
        try:limit=int(limit)
        except (TypeError,ValueError):return jsonify(error='Download limit must be a positive integer'),400
        if limit<1 or permission!='download':return jsonify(error='A positive download limit requires download permission'),400
    expires=None
    if data.get('expires_at'):
        try:expires=datetime.fromisoformat(data['expires_at'].replace('Z','+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:return jsonify(error='Invalid expiry date'),400
        if expires<=datetime.now(timezone.utc).replace(tzinfo=None):return jsonify(error='Expiry must be in the future'),400
    raw=secrets.token_urlsafe(32); link=PublicLink(document_id=doc.id,token_hash=hashlib.sha256(raw.encode()).hexdigest(),permission=permission,expires_at=expires,download_limit=limit)
    db.session.add(link); db.session.commit(); log('link_created',doc=doc)
    return jsonify(id=link.id,token=raw,permission=permission,expires_at=expires.isoformat() if expires else None,download_limit=limit),201

@app.get('/api/documents/<int:doc_id>/links')
@auth
def list_public_links(doc_id):
    doc=Document.query.filter_by(id=doc_id,owner_id=g.user_id).first_or_404(); rows=PublicLink.query.filter_by(document_id=doc.id).order_by(PublicLink.created_at.desc()).all()
    return jsonify([{'id':x.id,'permission':x.permission,'expires_at':x.expires_at.isoformat() if x.expires_at else None,'download_limit':x.download_limit,'download_count':x.download_count,'revoked':x.revoked_at is not None} for x in rows])

@app.delete('/api/links/<int:link_id>')
@auth
def revoke_public_link(link_id):
    link=PublicLink.query.get_or_404(link_id); doc=Document.query.filter_by(id=link.document_id,owner_id=g.user_id).first_or_404(); link.revoked_at=datetime.now(timezone.utc).replace(tzinfo=None); db.session.commit(); log('link_revoked',doc=doc); return jsonify(message='Protected link revoked')

@app.get('/api/public-links/<token>')
def public_link_info(token):
    link=active_public_link(token)
    if not link:return jsonify(error='This link is invalid, expired, revoked, or at its download limit'),404
    doc=Document.query.get_or_404(link.document_id); result=metadata(doc); result.update(permission=link.permission,expires_at=link.expires_at.isoformat() if link.expires_at else None,download_limit=link.download_limit,download_count=link.download_count)
    return jsonify(result)

def public_link_file(token,download):
    link=active_public_link(token)
    if not link:return jsonify(error='This link is invalid, expired, revoked, or at its download limit'),404
    if download and link.permission!='download':return jsonify(error='This link does not allow downloads'),403
    doc=Document.query.get_or_404(link.document_id)
    if not download and doc.filename.rsplit('.',1)[-1].lower() not in {'pdf','png','jpg','jpeg','txt'}:return jsonify(error='Inline preview is available for PDF, image, and text files'),415
    try:
        payload=(DATA_DIR/doc.blob_name).read_bytes(); raw=AESGCM(encryption_key()).decrypt(payload[:12],payload[12:],None)
    except Exception:
        log('public_access','error',doc,'Decryption or storage error'); return jsonify(error='Unable to decrypt document'),500
    if hashlib.sha256(raw).hexdigest()!=doc.sha256:log('integrity_check','failed',doc); return jsonify(error='Integrity verification failed'),409
    if download:
        q=PublicLink.query.filter_by(id=link.id,revoked_at=None)
        now=datetime.now(timezone.utc).replace(tzinfo=None)
        q=q.filter(or_(PublicLink.expires_at.is_(None),PublicLink.expires_at>now))
        if link.download_limit is not None:q=q.filter(PublicLink.download_count<link.download_limit)
        if q.update({PublicLink.download_count:PublicLink.download_count+1},synchronize_session=False)!=1:
            db.session.rollback(); return jsonify(error='Protected link was revoked, expired, or reached its limit'),404
        db.session.commit()
    log('public_download' if download else 'public_view',doc=doc)
    if download:return send_file(BytesIO(raw),download_name=doc.filename,as_attachment=True)
    ext=doc.filename.rsplit('.',1)[-1].lower(); mime={'pdf':'application/pdf','png':'image/png','jpg':'image/jpeg','jpeg':'image/jpeg','txt':'text/plain'}[ext]
    return send_file(BytesIO(raw),mimetype=mime,download_name=doc.filename,as_attachment=False)

@app.get('/api/public-links/<token>/preview')
def public_link_preview(token):return public_link_file(token,False)
@app.get('/api/public-links/<token>/download')
def public_link_download(token):return public_link_file(token,True)

@app.errorhandler(413)
def too_large(_):return jsonify(error='File exceeds the 20 MB limit'),413
@app.errorhandler(500)
def server_error(_):db.session.rollback(); return jsonify(error='Unexpected server error'),500
if __name__=='__main__':app.run(port=int(os.getenv('PORT','5000')),debug=os.getenv('FLASK_DEBUG')=='1')
