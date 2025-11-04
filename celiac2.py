# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message  # ✅ Tek import
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# --- PLACE THIS NEAR THE TOP, AFTER app = Flask(...) and db = SQLAlchemy(app) ---
from urllib.parse import quote_plus
import pytz

# Jinja filtre: url encode
def jinja_url_encode(value):
    if value is None:
        return ''
    return quote_plus(str(value))

app.jinja_env.filters['url_encode'] = jinja_url_encode

# Jinja filtre: Türkiye yerel saatli, okunabilir format
def jinja_turkish_datetime(value):
    if value is None:
        return ''
    try:
        # Eğer value timezone-aware değilse varsayımı UTC -> Istanbul
        # ve ardından Istanbul'a çevir
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            # treat as naive UTC
            dt_utc = pytz.UTC.localize(value)
        else:
            dt_utc = value.astimezone(pytz.UTC)
        tz = pytz.timezone('Europe/Istanbul')
        dt_local = dt_utc.astimezone(tz)
        return dt_local.strftime('%d.%m.%Y %H:%M')
    except Exception:
        try:
            # fallback naive formatting
            return value.strftime('%d.%m.%Y %H:%M')
        except Exception:
            return str(value)

app.jinja_env.filters['turkish_datetime'] = jinja_turkish_datetime
# -----------------------------------------------------------------------------
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.environ.get("DATABASE_URL"),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': os.environ.get("SECRET_KEY", "fallback_key"),
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USE_TLS': True,
    'MAIL_USE_SSL': False,
    'MAIL_USERNAME': os.environ.get("MAIL_USERNAME"),
    'MAIL_PASSWORD': os.environ.get("MAIL_PASSWORD"),
    'MAIL_DEFAULT_SENDER': os.environ.get("MAIL_USERNAME")
})

db = SQLAlchemy(app)
mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# En üste ekle:
import os
import requests

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDGRID_ENABLED = os.environ.get("SENDGRID_ENABLED", "false").lower() == "true"
SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL")

# SendGrid ile mail gönderme fonksiyonu
def sendgrid_send_confirmation_email(user_email, confirm_url):
    if not (SENDGRID_API_KEY and SENDGRID_FROM_EMAIL):
        print("❌ SendGrid API key veya FROM email eksik.")
        return False
    url = "https://api.sendgrid.com/v3/mail/send"
    data = {
        "personalizations": [{
            "to": [{"email": user_email}],
            "subject": "Glutasyon Üyeliğinizi Doğrulayın"
        }],
        "from": {"email": SENDGRID_FROM_EMAIL},
        "content": [{
            "type": "text/plain",
            "value": f"Merhaba! Kaydınızı tamamlamak için bu linke tıklayın:\n\n{confirm_url}"
        }]
    }
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        resp = requests.post(url, json=data, headers=headers)
        if resp.status_code in [200, 202]:
            print("✅ SendGrid ile email gönderildi!")
            return True
        else:
            print(f"❌ SendGrid hata: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        print(f"❌ SendGrid exception: {e}")
        return False

def send_confirmation_email(user_email):
    try:
        print(f"📧 Email gönderiliyor: {user_email}")
        print(f"📧 SMTP User: {app.config['MAIL_USERNAME']}")

        token = s.dumps(user_email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)

        msg = Message(
            subject="Glutasyon Üyeliğinizi Doğrulayın",
            recipients=[user_email],
            body=f"Merhaba! Kaydınızı tamamlamak için bu linke tıklayın:\n\n{confirm_url}"
        )

        mail.send(msg)
        print("✅ Email başarıyla gönderildi!")
        return True

    except Exception as e:
        print(f"❌ Email hatası: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# ------------------ MODELLER ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default="user")  # user / restaurant_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(200))
    is_file_upload = db.Column(db.Boolean, default=False)
    description = db.Column(db.Text)
    latitude = db.Column(db.Float)              # Konum
    longitude = db.Column(db.Float)             # Konum
    phone = db.Column(db.String(30))            # İletişim telefonu (YENİ)
    contact_email = db.Column(db.String(100))   # İletişim e-posta (YENİ)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    celiac_friendly = db.Column(db.Boolean, default=False)
    @property
    def image_full_url(self):
        if self.is_file_upload and self.image_url:
            return request.host_url.rstrip('/') + self.image_url
        return self.image_url

    products = db.relationship('Product', backref='restaurant', lazy=True)

from datetime import datetime
import pytz
from pytz import timezone, utc

def to_turkey_time(dt):
    if dt.tzinfo is None:
        dt = utc.localize(dt)
    return dt.astimezone(timezone('Europe/Istanbul'))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200))

class FavoriteRestaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

    restaurant = db.relationship('Restaurant', backref='favorite_restaurants')

class FavoriteProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

    product = db.relationship('Product', backref='favorite_products')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 arası puan
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Moderation fields (buffer / pending workflow)
    status = db.Column(db.String(20), default='pending')  # pending / approved / rejected
    pending_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)

    # Açıkça hangi foreign key'in hangi ilişkiye ait olduğunu belirt
    user = db.relationship('User', foreign_keys=[user_id], backref='comments')
    approved_user = db.relationship('User', foreign_keys=[approved_by], backref='approved_comments')

    restaurant = db.relationship('Restaurant', backref='comments')

class ProductComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 yıldız
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='product_comments')
    product = db.relationship('Product', backref='comments')

class BlogCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    blogs = db.relationship('Blog', backref='category', cascade='all, delete', lazy=True)

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    category_id = db.Column(db.Integer, db.ForeignKey('blog_category.id'), nullable=False)

    comments = db.relationship('BlogComment', back_populates='blog', cascade='all, delete', passive_deletes=True)
    likes = db.relationship('BlogLike', back_populates='blog', cascade='all, delete', passive_deletes=True)

class BlogComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('User', backref='blog_comments')
    blog = db.relationship('Blog', back_populates='comments')

class BlogLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id', ondelete='CASCADE'), nullable=False)

    user = db.relationship('User', backref='blog_likes')
    blog = db.relationship('Blog', back_populates='likes')

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='recipes')

class RestaurantApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    phone = db.Column(db.String(30))           # ← EKLEDİK
    contact_email = db.Column(db.String(100))  # ← EKLEDİK
    latitude = db.Column(db.Float)             # ← EKLEDİK (isteğe bağlı)
    longitude = db.Column(db.Float)            # ← EKLEDİK (isteğe bağlı)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    cross_contamination = db.Column(db.Boolean, default=False)  # Çapraz bulaşa dikkat ediyor musunuz?
    celiac_friendly = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="applications")

class RestaurantApplicationProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("restaurant_application.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)

    application = db.relationship("RestaurantApplication", backref="products")

# Add these imports near top of your celiac2.py
from sqlalchemy import Numeric
from slugify import slugify  # optional: pip install python-slugify
from decimal import Decimal
from datetime import datetime

# -----------------------------
# Event & EventRSVP MODELLER
# -----------------------------
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # etkinlik oluşturan (restoran admin)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(250), nullable=False, unique=True)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(400))
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=True)
    capacity = db.Column(db.Integer, nullable=True)     # kontenjan
    price = db.Column(Numeric(8, 2), nullable=True)     # ücret (opsiyonel)
    is_public = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='published')  # draft / published / canceled
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())
    payment_url = db.Column(db.String(500), nullable=True)  # opsiyonel: restoranın dış ödeme/bilet linki

    restaurant = db.relationship('Restaurant', backref='events')
    creator = db.relationship('User', foreign_keys=[creator_id], backref='created_events')

    def ensure_slug(self):
        # create readable unique slug; fallback to id if collision (ensure committed to generate id)
        if not self.slug and self.title:
            base = slugify(self.title)[:200] if 'slugify' in globals() else self.title.lower().replace(' ', '-')[:200]
            slug = base
            i = 1
            while Event.query.filter_by(slug=slug).first():
                i += 1
                slug = f"{base}-{i}"
            self.slug = slug

class EventRSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='going')  # going / maybe / canceled
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    event = db.relationship('Event', backref='rsvps')
    user = db.relationship('User', backref='event_rsvps')

# -----------------------------
# EVENT ROUTES (CRUD + Public + RSVP)
# -----------------------------

@app.route('/restaurant-admin/events')
def restaurant_admin_events():
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Bu alana erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    restaurants = Restaurant.query.filter_by(owner_id=user_id).all()
    restaurant_ids = [r.id for r in restaurants]

    events = Event.query.filter(Event.restaurant_id.in_(restaurant_ids)).order_by(Event.starts_at.asc()).all() if restaurant_ids else []

    # convert times for display
    for e in events:
        if e.starts_at:
            e.starts_at = to_turkey_time(e.starts_at)
        if e.ends_at:
            e.ends_at = to_turkey_time(e.ends_at)

    return render_template('restaurant_admin/events_list.html', events=events, restaurants=restaurants)

# Replace the POST handling in restaurant_admin_event_new with this (entire function)
@app.route('/restaurant-admin/events/new', methods=['GET', 'POST'])
def restaurant_admin_event_new():
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    restaurants = Restaurant.query.filter_by(owner_id=user_id).all()
    if not restaurants:
        flash("Herhangi bir restorana sahip değilsiniz.", "danger")
        return redirect(url_for('restaurant_admin_dashboard'))

    if request.method == 'POST':
        try:
            # restaurant seçimi
            try:
                restaurant_id = int(request.form.get('restaurant_id', '0'))
            except Exception:
                flash("Restoran seçimi geçersiz.", "danger")
                return redirect(url_for('restaurant_admin_event_new'))

            if restaurant_id not in [r.id for r in restaurants]:
                flash("Seçilen restorana yetkiniz yok.", "danger")
                return redirect(url_for('restaurant_admin_event_new'))

            # zorunlu alanlar
            title = (request.form.get('title') or '').strip()
            starts_at_raw = (request.form.get('starts_at') or '').strip()
            if not title or not starts_at_raw:
                flash("Başlık ve başlangıç zamanı zorunludur.", "danger")
                return redirect(url_for('restaurant_admin_event_new'))

            # diğer alanlar
            description = request.form.get('description') or None
            ends_at_raw = (request.form.get('ends_at') or '').strip()
            capacity = request.form.get('capacity', type=int) or None
            price_raw = (request.form.get('price') or '').strip()
            payment_url = request.form.get('payment_url') or None

            # tarih parsing - mevcut format YYYY-MM-DD HH:MM
            try:
                starts_dt = datetime.strptime(starts_at_raw, '%Y-%m-%d %H:%M')
            except Exception:
                flash("Başlangıç tarihi formatı geçersiz. YYYY-MM-DD HH:MM", "danger")
                return redirect(url_for('restaurant_admin_event_new'))

            ends_dt = None
            if ends_at_raw:
                try:
                    ends_dt = datetime.strptime(ends_at_raw, '%Y-%m-%d %H:%M')
                except Exception:
                    flash("Bitiş tarihi formatı geçersiz. YYYY-MM-DD HH:MM", "danger")
                    return redirect(url_for('restaurant_admin_event_new'))

            # fiyat parse
            try:
                price = Decimal(price_raw) if price_raw else None
            except Exception:
                flash("Ücret formatı geçersiz. Örnek: 49.90", "danger")
                return redirect(url_for('restaurant_admin_event_new'))

            # Event oluştur
            ev = Event(
                restaurant_id=restaurant_id,
                creator_id=user_id,
                title=title,
                description=description,
                starts_at=starts_dt,
                ends_at=ends_dt,
                capacity=capacity,
                price=price,
                payment_url=payment_url,
                is_public=True,
                status='published'
            )
            ev.ensure_slug()
            db.session.add(ev)
            db.session.commit()

            # garanti slug
            if not ev.slug:
                ev.slug = f"event-{ev.id}"
                db.session.commit()

            flash("Etkinlik oluşturuldu.", "success")
            return redirect(url_for('restaurant_admin_events'))

        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("DB hata - event oluşturma")
            flash("Veritabanı hatası oluştu. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for('restaurant_admin_event_new'))

    return render_template('restaurant_admin/event_new.html', restaurants=restaurants)
# Replace the POST handling in restaurant_admin_event_edit with this (entire function)
@app.route('/restaurant-admin/events/<int:event_id>/edit', methods=['GET', 'POST'])
def restaurant_admin_event_edit(event_id):
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    ev = Event.query.get_or_404(event_id)
    user_id = session['user_id']
    restaurant = Restaurant.query.get(ev.restaurant_id)
    if not restaurant or restaurant.owner_id != user_id:
        flash("Bu etkinliği düzenleme yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_admin_events'))

    if request.method == 'POST':
        try:
            ev.title = (request.form.get('title') or ev.title).strip()
            ev.description = request.form.get('description') or ev.description

            starts_at_raw = (request.form.get('starts_at') or '').strip()
            ends_at_raw = (request.form.get('ends_at') or '').strip()

            try:
                if starts_at_raw:
                    ev.starts_at = datetime.strptime(starts_at_raw, '%Y-%m-%d %H:%M')
                if ends_at_raw:
                    ev.ends_at = datetime.strptime(ends_at_raw, '%Y-%m-%d %H:%M')
                else:
                    ev.ends_at = None
            except Exception:
                flash("Tarih formatı geçersiz.", "danger")
                return redirect(url_for('restaurant_admin_event_edit', event_id=event_id))

            ev.capacity = request.form.get('capacity', type=int) or None

            price_raw = (request.form.get('price') or '').strip()
            try:
                ev.price = Decimal(price_raw) if price_raw else None
            except Exception:
                flash("Ücret formatı geçersiz. Örnek: 49.90", "danger")
                return redirect(url_for('restaurant_admin_event_edit', event_id=event_id))

            # sadece payment_url kaydet (başka ekstra alan yok)
            ev.payment_url = request.form.get('payment_url') or None

            ev.ensure_slug()
            db.session.commit()
            flash("Etkinlik güncellendi.", "success")
            return redirect(url_for('restaurant_admin_events'))

        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("DB hata - event güncelleme")
            flash("Veritabanı hatası oluştu. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for('restaurant_admin_event_edit', event_id=event_id))

    display_starts = ev.starts_at.strftime('%Y-%m-%d %H:%M') if ev.starts_at else ''
    display_ends = ev.ends_at.strftime('%Y-%m-%d %H:%M') if ev.ends_at else ''
    display_payment_url = ev.payment_url or ''
    return render_template('restaurant_admin/event_edit.html',
                           event=ev,
                           display_starts=display_starts,
                           display_ends=display_ends,
                           display_payment_url=display_payment_url)


@app.route('/restaurant-admin/events/<int:event_id>/delete', methods=['POST'])
def restaurant_admin_event_delete(event_id):
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    ev = Event.query.get_or_404(event_id)
    user_id = session['user_id']
    restaurant = Restaurant.query.get(ev.restaurant_id)
    if not restaurant or restaurant.owner_id != user_id:
        flash("Bu etkinliği silme yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_admin_events'))

    # Delete RSVPs first (optional cascade)
    EventRSVP.query.filter_by(event_id=ev.id).delete()
    db.session.delete(ev)
    db.session.commit()
    flash("Etkinlik silindi.", "success")
    return redirect(url_for('restaurant_admin_events'))

# Public routes
@app.route('/restaurants/<int:restaurant_id>/events')
def restaurant_events_public(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    events = Event.query.filter_by(restaurant_id=restaurant_id, status='published', is_public=True).order_by(Event.starts_at.asc()).all()
    for e in events:
        if e.starts_at:
            e.starts_at = to_turkey_time(e.starts_at)
        if e.ends_at:
            e.ends_at = to_turkey_time(e.ends_at)
    return render_template('events/public_list.html', restaurant=restaurant, events=events)

from sqlalchemy import func

@app.route('/events/<slug>')
def event_detail(slug):
    ev = Event.query.filter_by(slug=slug, status='published', is_public=True).first_or_404()

    # convert times for display (Turkey time)
    try:
        ev.starts_at = to_turkey_time(ev.starts_at) if ev.starts_at else None
    except Exception:
        pass
    try:
        ev.ends_at = to_turkey_time(ev.ends_at) if ev.ends_at else None
    except Exception:
        pass

    # prepare display values
    starts_display = ev.starts_at.strftime('%d.%m.%Y %H:%M') if ev.starts_at else ''
    ends_display = ev.ends_at.strftime('%d.%m.%Y %H:%M') if ev.ends_at else ''
    capacity_display = ev.capacity if ev.capacity is not None else None
    price_display = f"{float(ev.price):.2f} TL" if ev.price is not None else None

    return render_template('events/detail.html',
                           event=ev,
                           starts_display=starts_display,
                           ends_display=ends_display,
                           capacity_display=capacity_display,
                           price_display=price_display)

@app.route('/events/<int:event_id>/rsvp', methods=['POST'])
def event_rsvp(event_id):
    if not session.get('user_id'):
        flash("Katılmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    ev = Event.query.get_or_404(event_id)
    user_id = session['user_id']

    going_count = EventRSVP.query.filter_by(event_id=event_id, status='going').count()
    if ev.capacity and going_count >= ev.capacity:
        flash("Üzgünüz, etkinlik kontenjanı dolu.", "danger")
        return redirect(url_for('event_detail', slug=ev.slug))

    existing = EventRSVP.query.filter_by(event_id=event_id, user_id=user_id).first()
    if existing:
        existing.status = 'going'
        db.session.commit()
        flash("Katılımınız güncellendi.", "success")
    else:
        r = EventRSVP(event_id=event_id, user_id=user_id, status='going')
        db.session.add(r)
        db.session.commit()
        flash("Etkinliğe kayıt yapıldı.", "success")

    return redirect(url_for('event_detail', slug=ev.slug))

# Add this context processor somewhere after your `app` is created (e.g. after app = Flask(...))
from datetime import datetime
from sqlalchemy import asc

@app.context_processor
def inject_upcoming_events():
    """
    Adds `upcoming_events` to all templates.
    - Shows up to 5 next published, public events whose starts_at >= now (UTC).
    - Wrapped in try/except so templates still render if DB/table missing.
    """
    try:
        now = datetime.utcnow()
        upcoming = Event.query.filter(
            Event.status == 'published',
            Event.is_public == True,
            Event.starts_at >= now
        ).order_by(asc(Event.starts_at)).limit(5).all()

        # Convert times to Turkey time for display if you have to_turkey_time util
        for e in upcoming:
            if getattr(e, 'starts_at', None):
                try:
                    e.starts_at = to_turkey_time(e.starts_at)
                except Exception:
                    # fallback: leave as-is if conversion fails
                    pass
            if getattr(e, 'ends_at', None):
                try:
                    e.ends_at = to_turkey_time(e.ends_at)
                except Exception:
                    pass

    except Exception:
        upcoming = []

    return dict(upcoming_events=upcoming)

# ------------------ ROUTELAR ------------------

@app.route('/')
def index():
    return render_template('index.html')

import logging
logging.basicConfig(level=logging.INFO)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            logging.info("Kayıt isteği alındı.")

            # Form-data veya JSON desteği
            if request.is_json:
                data = request.get_json()
                email = data.get("email")
                username = data.get("username")
                password = data.get("password")
            else:
                email = request.form.get("email")
                username = request.form.get("username")
                password = request.form.get("password")

            logging.info(f"Gelen kayıt: email={email}, username={username}")

            # Boş alan kontrolü
            if not email or not username or not password:
                msg = "Tüm alanlar zorunludur."
                logging.warning(msg)
                if request.is_json:
                    return jsonify({"error": msg}), 400
                flash(msg, "warning")
                return redirect(url_for("register"))

            # E-posta zaten kayıtlı mı?
            existing_user = db.session.execute(
                db.select(User).filter_by(email=email)
            ).scalar()
            if existing_user:
                msg = "Bu e-posta zaten kayıtlı."
                logging.warning(msg)
                if request.is_json:
                    return jsonify({"error": msg}), 400
                flash(msg, "danger")
                return redirect(url_for("register"))

            # E-posta onay maili hazırlama
            try:
                token = s.dumps(email, salt='email-confirm')
                confirm_url = url_for('confirm_email', token=token, _external=True)

                # --- SENDGRID ENTEGRASYONU ---
                mail_success = False
                if SENDGRID_ENABLED:
                    mail_success = sendgrid_send_confirmation_email(email, confirm_url)
                else:
                    msg = Message(
                        "Glutasyon Üyeliğinizi Doğrulayın",
                        recipients=[email],
                        body=f"Merhaba! Kaydınızı tamamlamak için bu linke tıklayın:\n\n{confirm_url}"
                    )
                    mail.send(msg)
                    mail_success = True

                if not mail_success:
                    raise Exception("E-posta gönderilemedi (SendGrid veya Flask-Mail).")

                logging.info(f"Onay maili gönderildi: {email}")
            except Exception as e:
                logging.error(f"E-posta gönderilemedi: {e}")
                import traceback
                traceback.print_exc()
                if request.is_json:
                    return jsonify({"error": "Email gönderilemedi", "details": str(e)}), 500
                flash("Email gönderilemedi. Lütfen tekrar deneyin.", "danger")
                return redirect(url_for("register"))

            # Kullanıcıyı oluştur
            user = User(email=email, username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logging.info(f"Kullanıcı oluşturuldu: {user.id}")

            if request.is_json:
                return jsonify({
                    "message": "Kaydınız başarılı! Lütfen e-postanızı onaylayın.",
                    "user_id": user.id
                }), 201
            flash("Kaydınız başarılı! Lütfen e-postanızı onaylayın.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            db.session.rollback()
            logging.error(f"register fonksiyonu genel hata: {e}")
            import traceback
            traceback.print_exc()
            if request.is_json:
                return jsonify({"error": "Sunucu hatası", "details": str(e)}), 500
            flash("Bir hata oluştu. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Kullanıcı bulunamadı.", "danger")
            return redirect(url_for("login"))

        if not user.check_password(password):
            flash("Şifre hatalı.", "danger")
            return redirect(url_for("login"))

        if not user.confirmed:
            flash("Lütfen önce e-postanızı onaylayın.", "warning")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["username"] = user.username
        session["is_admin"] = user.is_admin
        session["role"] = user.role
        flash("Giriş başarılı!", "success")

        # Rol kontrolü ile otomatik panel yönlendirme
        if user.is_admin:
            return redirect(url_for("admin_dashboard"))
        elif user.role == "restaurant_admin":
            return redirect(url_for("restaurant_admin_dashboard"))
        else:
            return redirect(url_for("profile"))

    return render_template("login.html")

@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        return "Link geçersiz veya süresi dolmuş.", 400

    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        return "Zaten onaylamışsınız."

    user.confirmed = True
    db.session.commit()
    return "E-posta başarıyla onaylandı. Artık giriş yapabilirsiniz."

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'JSON verisi gerekli!'}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Kullanıcı adı ve şifre gerekli!'}), 400

        # Email formatında mı kontrol et
        if '@' in username:
            user = User.query.filter_by(email=username).first()
        else:
            user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            return jsonify({'error': 'Giriş başarısız!'}), 401

        if not user.confirmed:
            return jsonify({'error': 'E-posta adresinizi doğrulamanız gerekiyor.'}), 403

        return jsonify({
            'message': 'Giriş başarılı!',
            'user_id': user.id,
            'username': user.username,
            'confirmed': user.confirmed
        }), 200

    except Exception as e:
        print(f"Hata: {e}")
        return jsonify({'error': 'Sunucu hatası'}), 500

@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('index'))

@app.route('/restaurants')
def restaurants():
    selected_city = request.args.get('city')
    selected_category = request.args.get('category')

    query = Restaurant.query

    if selected_city:
        query = query.filter_by(city=selected_city)
    if selected_category:
        query = query.filter_by(category=selected_category)

    restaurants = query.all()

    cities = db.session.query(Restaurant.city).distinct().all()
    categories = db.session.query(Restaurant.category).distinct().all()

    return render_template('restaurants.html',
                           restaurants=restaurants,
                           cities=cities,
                           categories=categories,
                           selected_city=selected_city)

# --- Replace or update the existing restaurant_detail view with this version ---
from datetime import datetime

@app.route('/restaurants/<int:id>')
def restaurant_detail(id):
    restaurant = Restaurant.query.get_or_404(id)

    # Only fetch APPROVED comments for public view
    comments = Comment.query.filter_by(restaurant_id=id, status='approved').order_by(Comment.created_at.desc()).all()

    products = Product.query.filter_by(restaurant_id=id).all()

    # convert times to Turkey timezone for display
    for comment in comments:
        if comment.created_at:
            comment.created_at = to_turkey_time(comment.created_at)

    grouped_products = {}
    for product in products:
        category = product.category or 'Diğer'
        grouped_products.setdefault(category, []).append(product)

    return render_template(
        'restaurant_detail.html',
        restaurant=restaurant,
        grouped_products=grouped_products,
        comments=comments
    )

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'logos')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/admin/add-restaurant', methods=['GET', 'POST'])
def add_restaurant():
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        image_url = request.form.get('image_url', '')
        image_file = request.files.get('image_file')
        is_file_upload = False

        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            image_file.save(filepath)
            image_url = f'/static/uploads/logos/{filename}'
            is_file_upload = True

        new_restaurant = Restaurant(
            name=request.form['name'],
            address=request.form['address'],
            city=request.form['city'],
            category=request.form['category'],
            image_url=image_url,
            is_file_upload=is_file_upload,
            description=request.form['description'],
            latitude=request.form.get('latitude', type=float),
            longitude=request.form.get('longitude', type=float)
        )
        db.session.add(new_restaurant)
        db.session.commit()
        flash("Restoran eklendi.", "success")
        return redirect(url_for('restaurants'))

    return render_template('admin/add_restaurant.html')

@app.route('/admin/edit-restaurant/<int:id>', methods=['GET', 'POST'])
def edit_restaurant(id):
    restaurant = Restaurant.query.get_or_404(id)
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    if not (is_admin or (user_id and restaurant.owner_id == user_id)):
        flash("Sadece admin veya restoran sahibi düzenleyebilir.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        restaurant.name = request.form['name']
        restaurant.address = request.form['address']
        restaurant.city = request.form['city']
        restaurant.category = request.form['category']
        restaurant.description = request.form['description']
        restaurant.latitude = request.form.get('latitude', type=float)
        restaurant.longitude = request.form.get('longitude', type=float)

        new_image_url = request.form.get('image_url', '')
        new_image_file = request.files.get('image_file')

        if new_image_file and new_image_file.filename != '':
            filename = secure_filename(new_image_file.filename)
            upload_path = os.path.join(app.root_path, 'static', 'uploads', 'logos')
            os.makedirs(upload_path, exist_ok=True)
            file_path = os.path.join(upload_path, filename)
            new_image_file.save(file_path)

            restaurant.image_url = f'/static/uploads/logos/{filename}'
            restaurant.is_file_upload = True

        elif new_image_url:
            restaurant.image_url = new_image_url
            restaurant.is_file_upload = False

        db.session.commit()
        flash("Restoran güncellendi.", "success")
        return redirect(url_for('restaurants'))

    return render_template('admin/edit_restaurant.html', restaurant=restaurant)

# Replace existing restaurant_admin_dashboard view with this version
from datetime import datetime

@app.route('/restaurant-admin/dashboard')
def restaurant_admin_dashboard():
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Bu alana erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    restaurants = Restaurant.query.filter_by(owner_id=user_id).all()
    restaurant_ids = [r.id for r in restaurants]

    products = Product.query.filter(Product.restaurant_id.in_(restaurant_ids)).all() if restaurant_ids else []

    # show all comments related to their restaurants (including pending)
    comments = Comment.query.filter(Comment.restaurant_id.in_(restaurant_ids)).order_by(Comment.created_at.desc()).all() if restaurant_ids else []

    favorite_counts = {r.id: FavoriteRestaurant.query.filter_by(restaurant_id=r.id).count() for r in restaurants}

    # Calculate average rating across APPROVED comments for this restaurant admin's restaurants
    approved_comments = [c for c in comments if getattr(c, 'status', None) == 'approved' and getattr(c, 'rating', None) is not None]
    if approved_comments:
        total = sum(int(c.rating) for c in approved_comments)
        avg_rating = round(total / len(approved_comments), 2)
    else:
        avg_rating = None  # template will show '-'

    # convert created_at to Turkey time for display (optional)
    for c in comments:
        if c.created_at:
            c.created_at = to_turkey_time(c.created_at)

    return render_template('restaurant_admin/admin_dashboard.html',
                           restaurants=restaurants,
                           products=products,
                           comments=comments,
                           favorite_counts=favorite_counts,
                           avg_rating=avg_rating)

@app.route('/admin/delete-restaurant/<int:id>', methods=['POST'])
def delete_restaurant(id):
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    restaurant = Restaurant.query.get_or_404(id)
    FavoriteRestaurant.query.filter_by(restaurant_id=restaurant.id).delete()
    Comment.query.filter_by(restaurant_id=restaurant.id).delete()
    Product.query.filter_by(restaurant_id=restaurant.id).delete()

    if restaurant.is_file_upload:
        try:
            file_path = os.path.join(app.root_path, restaurant.image_url.lstrip('/'))
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print("Dosya silme hatası:", e)

    db.session.delete(restaurant)
    db.session.commit()
    flash("Restoran silindi.", "success")
    return redirect(url_for('restaurants'))

@app.route('/admin/product_comment')
def admin_product_comments():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comments = ProductComment.query.order_by(ProductComment.created_at.desc()).all()
    return render_template('admin/product_comment.html', comments=comments)

@app.route('/admin/delete_product_comment/<int:comment_id>', methods=['POST'])
def admin_delete_product_comment(comment_id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comment = ProductComment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Yorum silindi.", "success")
    return redirect(url_for('admin_product_comments'))

@app.route('/admin/restaurant_comments')
def admin_restaurant_comments():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('admin/restaurant_comments.html', comments=comments)

@app.route('/admin/delete_restaurant_comment/<int:comment_id>', methods=['POST'])
def admin_delete_restaurant_comment(comment_id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Restoran yorumu silindi.", "success")
    return redirect(url_for('admin_restaurant_comments'))

@app.route('/admin/blog_likes')
def admin_blog_likes():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    likes = BlogLike.query.order_by(BlogLike.id.desc()).all()
    return render_template('admin/blog_likes.html', likes=likes)

@app.route('/admin/favorite_restaurants')
def admin_favorite_restaurants():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    favorites = FavoriteRestaurant.query.all()
    return render_template('admin/favorite_restaurants.html', favorites=favorites)

@app.route('/admin/favorite_products')
def admin_favorite_products():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    favorites = FavoriteProduct.query.all()
    return render_template('admin/favorite_products.html', favorites=favorites)

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    # Artık hem admin hem de restaurant_admin bu route'a erişebilir.
    if not session.get('user_id') or not (session.get('is_admin') or session.get('role') == 'restaurant_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    is_admin = bool(session.get('is_admin'))
    is_restaurant_admin = session.get('role') == 'restaurant_admin'

    # Admin tüm restoranları görür; restaurant_admin yalnızca kendine ait olanları görür.
    if is_admin:
        restaurants = Restaurant.query.all()
    else:
        restaurants = Restaurant.query.filter_by(owner_id=user_id).all()

    if request.method == 'POST':
        # restaurant_id zorunlu
        restaurant_id = request.form.get('restaurant_id', type=int)
        if not restaurant_id:
            flash("Restoran seçimi zorunlu.", "danger")
            return redirect(url_for('add_product'))

        restaurant_obj = Restaurant.query.get(restaurant_id)
        if not restaurant_obj:
            flash("Seçilen restoran bulunamadı.", "danger")
            return redirect(url_for('add_product'))

        # Eğer kullanıcı restoran admini ise, seçilen restoranın kendisine ait olduğundan emin ol
        if is_restaurant_admin and restaurant_obj.owner_id != user_id:
            flash("Bu restorana ürün ekleme yetkiniz yok.", "danger")
            return redirect(url_for('add_product'))

        new_product = Product(
            name=request.form['name'],
            category=request.form['category'],
            description=request.form.get('description'),
            image_url=request.form.get('image_url'),
            restaurant_id=restaurant_id
        )
        db.session.add(new_product)
        db.session.commit()
        flash("Ürün eklendi.", "success")

        # Doğru dashboarda yönlendir
        if is_admin:
            return redirect(url_for('restaurants'))
        else:
            return redirect(url_for('restaurant_admin_dashboard'))

    return render_template('admin/add_product.html', restaurants=restaurants)

@app.route('/admin/edit-product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    if not session.get('user_id'):
        flash("İşlem için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    product = Product.query.get_or_404(id)
    restaurant = Restaurant.query.get(product.restaurant_id)
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    is_restaurant_admin = session.get('role') == "restaurant_admin"

    if not (is_admin or (is_restaurant_admin and restaurant.owner_id == user_id)):
        flash("Sadece admin veya ürünün ait olduğu restoranın sahibi düzenleyebilir.", "danger")
        if is_restaurant_admin:
            return redirect(url_for('restaurant_admin_dashboard'))
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        product.name = request.form['name']
        product.category = request.form['category']
        product.image_url = request.form['image_url']
        product.description = request.form['description']

        try:
            db.session.commit()
            flash("Ürün başarıyla güncellendi.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Bir hata oluştu: {str(e)}", "danger")

        # Doğru dashboarda yönlendir!
        if is_admin:
            return redirect(url_for('admin_dashboard'))
        elif is_restaurant_admin:
            return redirect(url_for('restaurant_admin_dashboard'))
        else:
            return redirect(url_for('profile'))

    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/delete-product/<int:id>', methods=['POST'])
def delete_product(id):
    if not session.get('user_id'):
        flash("İşlem için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    product = Product.query.get_or_404(id)
    restaurant = Restaurant.query.get(product.restaurant_id)
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    is_restaurant_admin = session.get('role') == 'restaurant_admin'

    if not (is_admin or (is_restaurant_admin and restaurant.owner_id == user_id)):
        flash("Sadece admin veya ürünün ait olduğu restoranın sahibi silebilir.", "danger")
        if is_restaurant_admin:
            return redirect(url_for('restaurant_admin_dashboard'))
        return redirect(url_for('admin_dashboard'))

    FavoriteProduct.query.filter_by(product_id=product.id).delete()
    db.session.delete(product)
    db.session.commit()

    flash("Ürün ve ilişkili favori kayıtları başarıyla silindi.", "success")
    # Doğru dashboarda yönlendir!
    if is_admin:
        return redirect(url_for('admin_dashboard'))
    elif is_restaurant_admin:
        return redirect(url_for('restaurant_admin_dashboard'))
    else:
        return redirect(url_for('profile'))

@app.route('/admin/add-category', methods=['GET', 'POST'])
def add_category():
    if not session.get('is_admin'):
        flash('Yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']

        if BlogCategory.query.filter_by(name=name).first():
            flash('Bu kategori zaten mevcut.', 'danger')
            return redirect(url_for('add_category'))

        new_category = BlogCategory(name=name)
        db.session.add(new_category)
        db.session.commit()
        flash('Kategori başarıyla eklendi.', 'success')
        return redirect(url_for('add_category'))

    return render_template('admin/add_category.html')

@app.route('/admin/add-blog', methods=['GET', 'POST'])
def add_blog():
    if not session.get('is_admin'):
        flash('Yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

    categories = BlogCategory.query.all()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image_url = request.form['image_url']
        category_id = request.form['category_id']

        new_blog = Blog(
            title=title,
            content=content,
            image_url=image_url,
            category_id=category_id
        )

        db.session.add(new_blog)
        db.session.commit()
        flash('Blog yazısı başarıyla eklendi.', 'success')
        return redirect(url_for('add_blog'))

    return render_template('admin/add_blog.html', categories=categories)

@app.route('/products/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    comments = ProductComment.query.filter_by(product_id=product_id).all()
    return render_template('product_detail.html', product=product, comments=comments)

@app.route('/products/<int:product_id>/comment', methods=['POST'])
def add_product_comment(product_id):
    if not session.get('user_id'):
        flash("Yorum yapabilmek için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    text = request.form['text']
    rating = request.form['rating']

    if not rating or not text:
        flash("Yorum ve puan boş bırakılamaz.", "danger")
        return redirect(url_for('product_detail', product_id=product_id))

    new_comment = ProductComment(
        user_id=session['user_id'],
        product_id=product_id,
        rating=int(rating),
        text=text
    )
    db.session.add(new_comment)
    db.session.commit()

    flash("Yorum başarıyla eklendi!", "success")
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/products/comment/delete/<int:comment_id>', methods=['POST'])
def delete_product_comment(comment_id):
    comment = ProductComment.query.get_or_404(comment_id)

    if comment.user_id != session.get('user_id'):
        flash("Bu yorumu silmeye yetkiniz yok.", "danger")
        return redirect(url_for('product_detail', product_id=comment.product_id))

    db.session.delete(comment)
    db.session.commit()

    flash("Yorum başarıyla silindi.", "success")
    return redirect(url_for('product_detail', product_id=comment.product_id))

@app.route('/admin/blog_comments')
def admin_blog_comments():
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Bu sayfaya erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comments = BlogComment.query.order_by(BlogComment.created_at.desc()).all()
    return render_template('admin/blog_comments.html', comments=comments)

@app.route('/admin/delete_blog_comment/<int:comment_id>', methods=['POST'])
def admin_delete_blog_comment(comment_id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    comment = BlogComment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Blog yorumu silindi.", "success")
    return redirect(url_for('admin_blog_comments'))

@app.route('/favorite/restaurant/<int:id>')
def favorite_restaurant(id):
    if not session.get('user_id'):
        flash("Favorilere eklemek için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    fav = FavoriteRestaurant.query.filter_by(user_id=user_id, restaurant_id=id).first()

    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash("Restoran favorilerden kaldırıldı.", "info")
    else:
        new_fav = FavoriteRestaurant(user_id=user_id, restaurant_id=id)
        db.session.add(new_fav)
        db.session.commit()
        flash("Restoran favorilere eklendi!", "success")

    return redirect(request.referrer or url_for('restaurants'))

@app.route('/favorite/product/<int:id>')
def favorite_product(id):
    if not session.get('user_id'):
        flash("Favorilere eklemek için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    fav = FavoriteProduct.query.filter_by(user_id=user_id, product_id=id).first()

    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash("Ürün favorilerden kaldırıldı.", "info")
    else:
        new_fav = FavoriteProduct(user_id=user_id, product_id=id)
        db.session.add(new_fav)
        db.session.commit()
        flash("Ürün favorilere eklendi!", "success")

    return redirect(request.referrer or url_for('restaurants'))

@app.route('/profile')
def profile():
    if not session.get('user_id'):
        flash("Profil sayfası için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    favorite_restaurants = FavoriteRestaurant.query.filter_by(user_id=user_id).all()
    favorite_products = FavoriteProduct.query.filter_by(user_id=user_id).all()
    user_comments = Comment.query.filter_by(user_id=user_id, status='approved').all()

    for comment in user_comments:
        comment.created_at = to_turkey_time(comment.created_at)

    user_recipes = Recipe.query.filter_by(user_id=user_id).order_by(Recipe.created_at.desc()).all()
    liked_blogs = Blog.query.join(BlogLike).filter(BlogLike.user_id == user_id).order_by(Blog.created_at.desc()).all()

    return render_template(
        'profile.html',
        favorite_restaurants=favorite_restaurants,
        favorite_products=favorite_products,
        user_comments=user_comments,
        user_recipes=user_recipes,
        liked_blogs=liked_blogs
    )

@app.route('/restaurants/<int:restaurant_id>/comment', methods=['POST'])
def add_comment(restaurant_id):
    if not session.get('user_id'):
        flash("Yorum yapabilmek için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    text = request.form['text']
    rating = request.form['rating']

    if not rating or not text:
        flash("Yorum ve puan boş bırakılamaz.", "danger")
        return redirect(url_for('restaurant_detail', id=restaurant_id))

    now = datetime.utcnow()

    # New behavior: comments are buffered/pending until restaurant admin approves.
    new_comment = Comment(
        user_id=session['user_id'],
        restaurant_id=restaurant_id,
        rating=int(rating),
        text=text,
        status='pending',
        pending_at=now
    )
    db.session.add(new_comment)
    db.session.commit()

    # Flash a message to the user indicating the comment is in process
    flash("Yorumunuz işleme alındı. Restoran yöneticisi onayladıktan sonra yayınlanacaktır.", "info")

    # Optionally notify restaurant owner by email (if contact exists)
    try:
        restaurant = Restaurant.query.get(restaurant_id)
        if restaurant and restaurant.owner_id:
            owner = User.query.get(restaurant.owner_id)
            if owner and owner.email:
                confirm_url = url_for('restaurant_admin_dashboard', _external=True)
                try:
                    if SENDGRID_ENABLED:
                        sendgrid_send_confirmation_email(owner.email, confirm_url)
                    else:
                        msg = Message(subject="Yeni Yorum Onayı Bekliyor",
                                      recipients=[owner.email],
                                      body=f"Restoranınıza yeni bir yorum geldi. Panelden onaylayabilirsiniz: {confirm_url}")
                        mail.send(msg)
                except Exception as mail_e:
                    print("Owner notify mail error:", mail_e)
    except Exception as e:
        print("notify owner error:", e)

    return redirect(url_for('restaurant_detail', id=restaurant_id))

@app.route('/search')
def search():
    query = request.args.get('q', '')

    restaurants = Restaurant.query.filter(Restaurant.name.ilike(f"%{query}%")).all()

    products = Product.query.filter(Product.name.ilike(f"%{query}%")).all()

    return render_template('search_results.html', query=query, restaurants=restaurants, products=products)

@app.route('/delete-comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if not session.get('user_id'):
        flash("İşlem için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    is_restaurant_admin = session.get('role') == 'restaurant_admin'

    # Yetki kontrolü: Yorumu yazan kişi, admin veya restoran sahibi
    if not (
        is_admin or
        (is_restaurant_admin and restaurant.owner_id == user_id) or
        (comment.user_id == user_id)
    ):
        flash("Bu yorumu silme yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_detail', id=comment.restaurant_id))

    db.session.delete(comment)
    db.session.commit()
    flash("Yorum silindi.", "success")
    return redirect(url_for('restaurant_detail', id=comment.restaurant_id))

@app.route('/edit-comment/<int:comment_id>', methods=['GET', 'POST'])
def edit_comment(comment_id):
    if not session.get('user_id'):
        flash("İşlem için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)

    if comment.user_id != session['user_id']:
        flash("Bu yorumu düzenleme yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_detail', id=comment.restaurant_id))

    if request.method == 'POST':
        new_text = request.form['text']
        new_rating = request.form['rating']

        if not new_text or not new_rating:
            flash("Yorum ve puan boş bırakılamaz.", "danger")
            return redirect(url_for('edit_comment', comment_id=comment_id))

        comment.text = new_text
        comment.rating = int(new_rating)
        db.session.commit()

        flash("Yorum güncellendi.", "success")
        return redirect(url_for('restaurant_detail', id=comment.restaurant_id))

    return render_template('edit_comment.html', comment=comment)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('user_id'):
        flash("Şifre değiştirmek için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not user.check_password(current_password):
            flash("Mevcut şifreniz yanlış.", "danger")
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("Yeni şifreler eşleşmiyor.", "danger")
            return redirect(url_for('change_password'))

        user.set_password(new_password)
        db.session.commit()

        flash("Şifreniz başarıyla değiştirildi.", "success")
        return redirect(url_for('profile'))

    return render_template('change_password.html')

@app.route('/products')
def products():
    selected_category = request.args.get('category')

    query = Product.query

    if selected_category:
        query = query.filter_by(category=selected_category)

    products = query.all()

    categories = db.session.query(Product.category).distinct().all()

    return render_template('products.html', products=products, categories=categories)

@app.route('/nearby', methods=['GET', 'POST'])
def nearby():
    if request.method == 'POST':
        user_lat = float(request.form['latitude'])
        user_lng = float(request.form['longitude'])

        restaurants = Restaurant.query.all()
        nearby_restaurants = []

        for r in restaurants:
            if r.latitude and r.longitude:
                distance = haversine(user_lat, user_lng, r.latitude, r.longitude)
                nearby_restaurants.append((r, distance))

        nearby_restaurants.sort(key=lambda x: x[1])

        top_5 = nearby_restaurants[:5]

        return render_template('nearby.html', top_5=top_5)

    return render_template('nearby.html', top_5=[])

import math

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    distance = R * c
    return distance

@app.route('/blogs')
def blogs():
    blogs = Blog.query.order_by(Blog.created_at.desc()).all()
    categories = BlogCategory.query.all()
    return render_template('blogs.html', blogs=blogs, categories=categories)

@app.route('/blogs/category/<int:category_id>')
def blogs_by_category(category_id):
    blogs = Blog.query.filter_by(category_id=category_id).order_by(Blog.created_at.desc()).all()
    categories = BlogCategory.query.all()
    selected_category = BlogCategory.query.get_or_404(category_id)
    return render_template('blogs.html', blogs=blogs, categories=categories, selected_category=selected_category)

@app.route('/blogs/<int:blog_id>')
def blog_detail(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    categories = BlogCategory.query.all()
    for comment in blog.comments:
        comment.created_at = to_turkey_time(comment.created_at)
    return render_template('blog_detail.html', blog=blog, categories=categories)

@app.route('/blogs/<int:blog_id>/comment', methods=['POST'])
def add_blog_comment(blog_id):
    if not session.get('user_id'):
        flash('Yorum yapabilmek için giriş yapmalısınız.', 'danger')
        return redirect(url_for('login'))

    text = request.form['text']

    if not text.strip():
        flash('Yorum boş olamaz.', 'danger')
        return redirect(url_for('blog_detail', blog_id=blog_id))

    new_comment = BlogComment(
        user_id=session['user_id'],
        blog_id=blog_id,
        text=text
    )

    db.session.add(new_comment)
    db.session.commit()
    flash('Yorumunuz eklendi.', 'success')
    return redirect(url_for('blog_detail', blog_id=blog_id))

@app.route('/blogs/<int:blog_id>/like')
def like_blog(blog_id):
    if not session.get('user_id'):
        flash('Beğenebilmek için giriş yapmalısınız.', 'danger')
        return redirect(url_for('login'))

    existing_like = BlogLike.query.filter_by(user_id=session['user_id'], blog_id=blog_id).first()

    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        flash('Beğeni kaldırıldı.', 'info')
    else:
        new_like = BlogLike(user_id=session['user_id'], blog_id=blog_id)
        db.session.add(new_like)
        db.session.commit()
        flash('Beğenildi!', 'success')

    return redirect(url_for('blog_detail', blog_id=blog_id))

@app.route('/blogs/comment/delete/<int:comment_id>', methods=['POST'])
def delete_blog_comment(comment_id):
    comment = BlogComment.query.get_or_404(comment_id)

    if not session.get('user_id'):
        flash('Giriş yapmalısınız.', 'danger')
        return redirect(url_for('login'))

    if session['user_id'] != comment.user_id and not session.get('is_admin'):
        flash('Bu yorumu silme yetkiniz yok.', 'danger')
        return redirect(url_for('blog_detail', blog_id=comment.blog_id))

    db.session.delete(comment)
    db.session.commit()
    flash('Yorum silindi.', 'success')
    return redirect(url_for('blog_detail', blog_id=comment.blog_id))

@app.route('/blogs/comment/edit/<int:comment_id>', methods=['GET', 'POST'])
def edit_blog_comment(comment_id):
    comment = BlogComment.query.get_or_404(comment_id)

    if not session.get('user_id'):
        flash('Giriş yapmalısınız.', 'danger')
        return redirect(url_for('login'))

    if session['user_id'] != comment.user_id and not session.get('is_admin'):
        flash('Bu yorumu düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('blog_detail', blog_id=comment.blog_id))

    if request.method == 'POST':
        new_text = request.form['text']
        if not new_text.strip():
            flash('Yorum boş olamaz.', 'danger')
            return redirect(url_for('edit_blog_comment', comment_id=comment.id))

        comment.text = new_text
        db.session.commit()
        flash('Yorum güncellendi.', 'success')
        return redirect(url_for('blog_detail', blog_id=comment.blog_id))

    return render_template('edit_blog_comment.html', comment=comment)

@app.route('/blogs/<int:blog_id>/delete', methods=['POST'])
def delete_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)

    if not session.get('is_admin'):
        flash('Sadece admin blog silebilir.', 'danger')
        return redirect(url_for('blogs'))

    for comment in blog.comments:
        db.session.delete(comment)

    db.session.delete(blog)
    db.session.commit()
    flash('Blog ve tüm yorumları başarıyla silindi!', 'success')
    return redirect(url_for('blogs'))

@app.route('/blogs/<int:blog_id>/edit', methods=['GET', 'POST'])
def edit_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)

    if not session.get('is_admin'):
        flash('Sadece admin blog düzenleyebilir.', 'danger')
        return redirect(url_for('blogs'))

    if request.method == 'POST':
        blog.title = request.form['title']
        blog.content = request.form['content']
        blog.image_url = request.form['image_url']

        db.session.commit()
        flash('Blog başarıyla güncellendi!', 'success')
        return redirect(url_for('blog_detail', blog_id=blog.id))

    return render_template('edit_blog.html', blog=blog)

@app.route('/recipes/add', methods=['GET', 'POST'])
def add_recipe():
    if not session.get('user_id'):
        flash('Tarif eklemek için giriş yapmalısınız.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image_url = request.form['image_url']

        new_recipe = Recipe(
            user_id=session['user_id'],
            title=title,
            content=content,
            image_url=image_url
        )

        db.session.add(new_recipe)
        db.session.commit()
        flash('Tarif başarıyla eklendi!', 'success')
        return redirect(url_for('recipes'))

    return render_template('add_recipe.html')

@app.route('/recipes')
def recipes():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return render_template('recipes.html', recipes=recipes)

@app.route('/recipes/<int:id>')
def recipe_detail(id):
    recipe = Recipe.query.get_or_404(id)
    return render_template('recipe_detail.html', recipe=recipe)

@app.route('/recipes/<int:recipe_id>/delete', methods=['POST'])
def delete_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)

    if session.get('user_id') != recipe.user_id and not session.get('is_admin'):
        flash('Bu tarifi silme yetkiniz yok.', 'danger')
        return redirect(url_for('recipes'))

    db.session.delete(recipe)
    db.session.commit()
    flash('Tarif başarıyla silindi!', 'success')
    return redirect(url_for('recipes'))

@app.route('/recipes/<int:recipe_id>/edit', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)

    if session.get('user_id') != recipe.user_id and not session.get('is_admin'):
        flash('Bu tarifi düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('recipes'))

    if request.method == 'POST':
        recipe.title = request.form['title']
        recipe.content = request.form['content']
        recipe.image_url = request.form['image_url']

        db.session.commit()
        flash('Tarif başarıyla güncellendi!', 'success')
        return redirect(url_for('recipe_detail', id=recipe.id))

    return render_template('edit_recipe.html', recipe=recipe)

@app.route("/apply_restaurant", methods=["GET", "POST"])
def apply_restaurant():
    if not session.get("user_id"):
        flash("Başvuru yapabilmek için giriş yapmalısınız.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    existing = RestaurantApplication.query.filter_by(user_id=user_id, status="pending").first()
    if existing:
        flash("Zaten bekleyen bir başvurunuz var.", "warning")
        return redirect(url_for("profile"))

    if request.method == "POST":
        name = request.form["name"]
        address = request.form["address"]
        city = request.form["city"]
        category = request.form["category"]
        description = request.form["description"]
        phone = request.form.get("phone")
        contact_email = request.form.get("contact_email")
        latitude = request.form.get("latitude", type=float)
        longitude = request.form.get("longitude", type=float)

        # Yeni alanlar: formdaki 'yes'/'no' veya checkbox dönüyorsa uyarlanabilir
        cross = request.form.get('cross_contamination')
        celiac = request.form.get('celiac_friendly')
        # cross and celiac value parsing: 'yes' -> True, 'no' -> False; also checkbox case
        def _parse_bool(v):
            if v is None:
                return False
            v = str(v).lower()
            return v in ('1','true','yes','on','y')

        cross_val = _parse_bool(cross)
        celiac_val = _parse_bool(celiac)

        app_obj = RestaurantApplication(
            user_id=user_id,
            name=name,
            address=address,
            city=city,
            category=category,
            description=description,
            phone=phone,
            contact_email=contact_email,
            latitude=latitude,
            longitude=longitude,
            cross_contamination=cross_val,
            celiac_friendly=celiac_val
        )
        db.session.add(app_obj)
        db.session.commit()

        # ürünleri kaydet (mevcut davranış)
        for key in request.form:
            if key.startswith("products") and "[name]" in key:
                index = key.split("[")[1].split("]")[0]
                pname = request.form.get(f"products[{index}][name]")
                pcat = request.form.get(f"products[{index}][category]")
                pdesc = request.form.get(f"products[{index}][description]")
                if pname:
                    product = RestaurantApplicationProduct(
                        application_id=app_obj.id,
                        name=pname,
                        category=pcat,
                        description=pdesc
                    )
                    db.session.add(product)

        db.session.commit()
        flash("Başvurunuz alındı. Onay bekleniyor.", "success")
        return redirect(url_for("profile"))

    return render_template("apply_restaurant.html")

@app.route("/admin/applications")
def admin_applications():
    if not session.get("is_admin"):
        flash("Erişim izniniz yok.", "danger")
        return redirect(url_for("index"))

    applications = RestaurantApplication.query.order_by(RestaurantApplication.created_at.desc()).all()
    return render_template("admin/applications.html", applications=applications)


@app.route("/admin/applications/<int:app_id>/approve", methods=["POST"])
def approve_application(app_id):
    if not session.get("is_admin"):
        flash("Erişim izniniz yok.", "danger")
        return redirect(url_for("index"))

    application = RestaurantApplication.query.get_or_404(app_id)
    application.status = "approved"

    user = User.query.get(application.user_id)
    user.role = "restaurant_admin"

    # --- GÜNCELLENEN KISIM ---
    restaurant = Restaurant(
        name=application.name,
        address=application.address,
        city=application.city,
        category=application.category,
        description=application.description,
        owner_id=user.id,
        latitude=application.latitude,
        longitude=application.longitude,
        phone=application.phone,
        contact_email=application.contact_email
    )
    db.session.add(restaurant)
    db.session.commit()

    # Ürünleri ekle
    for ap in application.products:
        product = Product(
            restaurant_id=restaurant.id,
            name=ap.name,
            category=ap.category,
            description=ap.description
        )
        db.session.add(product)

    db.session.commit()
    flash("Başvuru onaylandı, restoran oluşturuldu.", "success")
    return redirect(url_for("admin_applications"))

@app.route("/admin/applications/<int:app_id>/reject", methods=["POST"])
def reject_application(app_id):
    if not session.get("is_admin"):
        flash("Erişim izniniz yok.", "danger")
        return redirect(url_for("index"))

    application = RestaurantApplication.query.get_or_404(app_id)
    application.status = "rejected"
    db.session.commit()

    flash("Başvuru reddedildi.", "info")
    return redirect(url_for("admin_applications"))

@app.route("/admin/applications/<int:app_id>")
def admin_application_detail(app_id):
    if not session.get("is_admin"):
        flash("Erişim izniniz yok.", "danger")
        return redirect(url_for("index"))

    application = RestaurantApplication.query.get_or_404(app_id)
    return render_template("admin/application_detail.html", application=application)

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("is_admin"):
        flash("Bu alana erişim yetkiniz yok.", "danger")
        return redirect(url_for("index"))

    user_count = User.query.count()
    restaurant_count = Restaurant.query.count()
    product_count = Product.query.count()
    comment_count = Comment.query.count()

    return render_template("admin/dashboard.html",
                           user_count=user_count,
                           restaurant_count=restaurant_count,
                           product_count=product_count,
                           comment_count=comment_count)

@app.route('/restaurant-admin/delete-comment/<int:comment_id>', methods=['POST'])
def restaurant_admin_delete_comment(comment_id):
    """Restoran admini kendi restoranına gelen yorumu silebilir."""
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Bu alana erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    comment = Comment.query.get_or_404(comment_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)

    if not restaurant or restaurant.owner_id != user_id:
        flash("Bu yorumu silmeye yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_admin_dashboard'))

    db.session.delete(comment)
    db.session.commit()
    flash("Yorum başarıyla silindi.", "success")
    return redirect(url_for('restaurant_admin_dashboard'))

@app.route('/restaurant-admin/comment/<int:comment_id>/approve', methods=['POST'])
def restaurant_admin_approve_comment(comment_id):
    """Restoran admini pending yorumları onaylayabilir."""
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Bu alana erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)
    user_id = session['user_id']

    if not restaurant or restaurant.owner_id != user_id:
        flash("Bu yorumu onaylama yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_admin_dashboard'))

    comment.status = 'approved'
    comment.approved_by = user_id
    comment.approved_at = datetime.utcnow()
    db.session.commit()
    flash("Yorum onaylandı ve yayınlandı.", "success")
    return redirect(url_for('restaurant_admin_dashboard'))

@app.route('/restaurant-admin/comment/<int:comment_id>/reject', methods=['POST'])
def restaurant_admin_reject_comment(comment_id):
    """Restoran admini pending yorumları reddedebilir (silme yerine status değiştirme tercih edilebilir)."""
    if not session.get('user_id') or session.get('role') != 'restaurant_admin':
        flash("Bu alana erişim izniniz yok.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)
    user_id = session['user_id']

    if not restaurant or restaurant.owner_id != user_id:
        flash("Bu yorumu reddetme yetkiniz yok.", "danger")
        return redirect(url_for('restaurant_admin_dashboard'))

    # Burada tamamen silme yerine 'rejected' yapıyoruz; geçmiş kalır.
    comment.status = 'rejected'
    comment.approved_by = user_id
    comment.approved_at = datetime.utcnow()
    db.session.commit()
    flash("Yorum reddedildi.", "info")
    return redirect(url_for('restaurant_admin_dashboard'))

from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --------------------------------------------
# 🔧 Yardımcı Fonksiyonlar
# --------------------------------------------

try:
    recipe_like_store
except NameError:
    recipe_like_store = {}

def _abs_image(url):
    """Görsel yollarını tam URL'e çevirir."""
    if not url:
        return ''
    url = str(url)
    return (request.host_url.rstrip('/') + url) if url.startswith('/static') else url

def _safe_text(v):
    return v or ''

# --------------------------------------------
# 🍽️ RESTORANLAR VE ÜRÜNLER
# --------------------------------------------
# --------------------------------------------
# 👤 KULLANICI PROFİL & FAVORİLER
# --------------------------------------------

@app.route('/api/user/<int:user_id>/profile')
def api_user_profile(user_id):
    """Kullanıcı profil bilgilerini getirir (beğenilen blog sayısı dahil)"""
    user = User.query.get_or_404(user_id)
    # Beğenilen blog sayısını hesapla
    liked_blogs_count = BlogLike.query.filter_by(user_id=user_id).count()
    favorite_restaurants_count = FavoriteRestaurant.query.filter_by(user_id=user_id).count()

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'liked_blogs_count': liked_blogs_count,
        'favorite_restaurants_count': favorite_restaurants_count
    })


@app.route('/api/user/<int:user_id>/favorites')
def api_user_favorites(user_id):
    """Kullanıcının favori restoranlarını getirir"""
    favorites = FavoriteRestaurant.query.filter_by(user_id=user_id).all()
    return jsonify([
        {
            'id': f.restaurant.id,
            'name': f.restaurant.name,
            'description': _safe_text(f.restaurant.description),
            'city': f.restaurant.city,
            'category': f.restaurant.category,
            'district': getattr(f.restaurant, 'district', '') or '',
            'address': _safe_text(f.restaurant.address),
            'image_url': _abs_image(f.restaurant.image_url),
            'latitude': f.restaurant.latitude,
            'longitude': f.restaurant.longitude,
            'is_file_upload': bool(f.restaurant.is_file_upload)
        }
        for f in favorites if f.restaurant
    ])


@app.route('/api/user/<int:user_id>/liked-blogs')
def api_user_liked_blogs(user_id):
    """Kullanıcının beğendiği blogları getirir"""
    liked_blogs = db.session.query(Blog).join(BlogLike).filter(BlogLike.user_id == user_id).order_by(
        Blog.created_at.desc()).all()
    return jsonify([
        {
            'id': b.id,
            'title': b.title,
            'content': b.content[:200] + '...' if len(b.content) > 200 else b.content,
            'image_url': _abs_image(b.image_url),
            'created_at': b.created_at.strftime('%Y-%m-%d') if b.created_at else ''
        } for b in liked_blogs
    ])


# --------------------------------------------
# 🍽️ RESTORANLAR
# --------------------------------------------

@app.route('/api/restaurants')
def api_restaurants():
    restaurants = Restaurant.query.all()
    return jsonify([
        {
            'id': r.id,
            'name': r.name,
            'description': _safe_text(r.description),
            'city': r.city,
            'category': r.category,
            'district': getattr(r, 'district', '') or '',
            'address': _safe_text(r.address),
            'image_url': _abs_image(r.image_url),
            'latitude': r.latitude,
            'longitude': r.longitude,
            'is_file_upload': bool(r.is_file_upload)
        }
        for r in restaurants
    ])


@app.route('/api/restaurants/<int:restaurant_id>')
def api_restaurant_detail(restaurant_id):
    """Restoran detayını getirir."""
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    return jsonify({
        'id': restaurant.id,
        'name': restaurant.name,
        'description': _safe_text(restaurant.description),
        'city': restaurant.city,
        'district': getattr(restaurant, 'district', '') or '',
        'address': _safe_text(restaurant.address),
        'image_url': _abs_image(restaurant.image_url),
        'latitude': restaurant.latitude,
        'longitude': restaurant.longitude,
        'category': restaurant.category,
        'is_file_upload': bool(restaurant.is_file_upload)
    })


@app.route('/api/restaurants/<int:restaurant_id>/favorite', methods=['POST'])
def api_toggle_restaurant_favorite(restaurant_id):
    """Restoran favorisini toggle eder"""
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'user_id zorunlu'}), 400

    # Mevcut favoriyi kontrol et
    existing_favorite = FavoriteRestaurant.query.filter_by(user_id=user_id, restaurant_id=restaurant_id).first()

    if existing_favorite:
        # Favoriden kaldır
        db.session.delete(existing_favorite)
        db.session.commit()
        return jsonify({'message': 'Favorilerden kaldırıldı', 'favorited': False}), 200
    else:
        # Favoriye ekle
        new_favorite = FavoriteRestaurant(user_id=user_id, restaurant_id=restaurant_id)
        db.session.add(new_favorite)
        db.session.commit()
        return jsonify({'message': 'Favorilere eklendi', 'favorited': True}), 201


@app.route('/api/restaurants/<int:restaurant_id>/favorite-status/<int:user_id>')
def api_restaurant_favorite_status(restaurant_id, user_id):
    """Kullanıcının restoranı favorilere ekleyip eklemediğini kontrol eder"""
    favorite = FavoriteRestaurant.query.filter_by(user_id=user_id, restaurant_id=restaurant_id).first()
    return jsonify({'favorited': bool(favorite)})


@app.route('/api/restaurants/<int:restaurant_id>/products')
def api_restaurant_products(restaurant_id):
    products = Product.query.filter_by(restaurant_id=restaurant_id).all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'category': p.category,
            'description': _safe_text(p.description),
            'image_url': _abs_image(p.image_url),
            'restaurant_id': p.restaurant_id
        }
        for p in products
    ])


@app.route('/api/products')
def api_products():
    restaurant_id = request.args.get('restaurant_id', type=int)
    products = Product.query.filter_by(restaurant_id=restaurant_id).all() if restaurant_id else Product.query.all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'description': _safe_text(p.description),
            'ingredients': _safe_text(p.description),
            'image_url': _abs_image(p.image_url),
            'restaurant_id': p.restaurant_id
        }
        for p in products
    ])


@app.route('/api/products/<int:product_id>')
def api_product_detail(product_id):
    p = Product.query.get_or_404(product_id)
    return jsonify({
        'id': p.id,
        'name': p.name,
        'description': _safe_text(p.description),
        'category': p.category,
        'image_url': _abs_image(p.image_url),
        'restaurant_id': p.restaurant_id
    })


# --------------------------------------------
# 📍 YAKIN RESTORANLAR
# --------------------------------------------

@app.route('/api/nearby', methods=['POST'])
def nearby_api():
    lat = request.form.get('latitude') or (request.json or {}).get('latitude')
    lng = request.form.get('longitude') or (request.json or {}).get('longitude')
    try:
        user_lat = float(lat)
        user_lng = float(lng)
    except Exception as e:
        return jsonify({"error": "Geçersiz konum bilgisi", "details": str(e)}), 400

    restaurants = Restaurant.query.all()
    items = []
    for r in restaurants:
        if r.latitude is not None and r.longitude is not None:
            d = haversine(user_lat, user_lng, r.latitude, r.longitude)
            items.append((r, d))

    items.sort(key=lambda x: x[1])
    top_5 = items[:5]

    return jsonify([
        {
            "id": r.id,
            "name": r.name,
            "description": _safe_text(r.description),
            "city": r.city,
            "district": getattr(r, 'district', '') or '',
            "address": _safe_text(r.address),
            "latitude": r.latitude,
            "longitude": r.longitude,
            "distance_km": round(d, 2),
            "image_url": _abs_image(r.image_url),
            "is_file_upload": bool(r.is_file_upload)
        }
        for (r, d) in top_5
    ])


# --------------------------------------------
# 📖 TARİFLER
# --------------------------------------------

@app.route('/api/recipes', methods=['GET'])
def api_recipes():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    return jsonify([
        {
            'id': r.id,
            'title': r.title,
            'content': r.content,
            'image_url': _abs_image(r.image_url),
            'user_id': r.user_id
        } for r in recipes
    ])


@app.route('/api/recipes', methods=['POST'])
def api_add_recipe():
    data = request.get_json(force=True, silent=True) or {}
    user_id, title, content = data.get('user_id'), data.get('title'), data.get('content')
    image_url = data.get('image_url', '')
    if not user_id or not title or not content:
        return jsonify({'error': 'Eksik bilgi'}), 400
    try:
        new_recipe = Recipe(user_id=user_id, title=title, content=content, image_url=image_url)
        db.session.add(new_recipe)
        db.session.commit()
        return jsonify({'message': 'Tarif eklendi'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# --------------------------------------------
# 📝 BLOG YAZILARI
# --------------------------------------------

@app.route('/api/blogs')
def api_blogs():
    """Tüm blog yazılarını listeler."""
    blogs = Blog.query.order_by(Blog.created_at.desc()).all()
    return jsonify([
        {
            'id': b.id,
            'title': b.title,
            'content': b.content[:200] + '...' if len(b.content) > 200 else b.content,
            'image_url': _abs_image(b.image_url),
            'created_at': b.created_at.strftime('%Y-%m-%d') if b.created_at else ''
        } for b in blogs
    ])


@app.route('/api/blogs/<int:blog_id>')
def api_blog_detail(blog_id):
    """Blog detayını getirir."""
    blog = Blog.query.get_or_404(blog_id)
    like_count = BlogLike.query.filter_by(blog_id=blog_id).count()
    return jsonify({
        'id': blog.id,
        'title': blog.title,
        'content': blog.content,
        'image_url': _abs_image(blog.image_url),
        'created_at': blog.created_at.strftime('%Y-%m-%d') if blog.created_at else '',
        'like_count': like_count

    })


@app.route('/api/blogs/<int:blog_id>/like', methods=['POST'])
def api_toggle_blog_like(blog_id):
    """Blog beğenisini toggle eder"""
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'user_id zorunlu'}), 400

    # Mevcut beğeniyi kontrol et
    existing_like = BlogLike.query.filter_by(user_id=user_id, blog_id=blog_id).first()

    if existing_like:
        # Beğeniyi kaldır
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'message': 'Beğeni kaldırıldı', 'liked': False}), 200
    else:
        # Beğeni ekle
        new_like = BlogLike(user_id=user_id, blog_id=blog_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'message': 'Beğeni eklendi', 'liked': True}), 201


@app.route('/api/blogs/<int:blog_id>/like-status/<int:user_id>')
def api_blog_like_status(blog_id, user_id):
    """Kullanıcının blogu beğenip beğenmediğini kontrol eder"""
    like = BlogLike.query.filter_by(user_id=user_id, blog_id=blog_id).first()
    return jsonify({'liked': bool(like)})


# --------------------------------------------
# 💬 YORUMLAR (EKLEME & LİSTELEME)
# --------------------------------------------

@app.route('/api/comments/restaurant/<int:restaurant_id>', methods=['GET'])
def get_comments_for_restaurant(restaurant_id):
    # Return only approved comments in the public API
    comments = Comment.query.filter_by(restaurant_id=restaurant_id, status='approved').all()
    return jsonify([
        {
            "id": c.id,
            "text": c.text,
            "rating": c.rating,
            "user": c.user.username if c.user else "Anonim",
            "user_id": c.user_id,
            "created_at": c.created_at.strftime("%Y-%m-%d %H:%M")
        }
        for c in comments
    ])


@app.route('/api/comments/restaurant', methods=['POST'])
def api_comment_restaurant():
    data = request.get_json(force=True, silent=True) or {}
    user_id, restaurant_id, rating, text = (
        data.get('user_id'),
        data.get('restaurant_id'),
        data.get('rating'),
        data.get('text'),
    )
    if not all([user_id, restaurant_id, rating, text]):
        return jsonify({'error': 'Tüm alanlar zorunludur'}), 400
    now = datetime.utcnow()
    new_comment = Comment(user_id=user_id, restaurant_id=restaurant_id, rating=int(rating), text=text,
                          status='pending', pending_at=now)
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({'message': 'Yorum işleme alındı (restoran onayı bekliyor).'}), 201


@app.route('/api/blogs/<int:blog_id>/comments')
def api_blog_comments(blog_id):
    comments = BlogComment.query.filter_by(blog_id=blog_id).order_by(BlogComment.created_at.desc()).all()
    return jsonify([
        {
            "id": c.id,
            "text": c.text,
            "user_id": c.user_id,
            "username": c.user.username if c.user else "Anonim",
            "created_at": c.created_at.strftime('%Y-%m-%d')
        }
        for c in comments
    ])


@app.route('/api/blogs/<int:blog_id>/comment', methods=['POST'])
def api_add_blog_comment(blog_id):
    data = request.get_json(force=True, silent=True) or {}
    user_id, text = data.get('user_id'), data.get('text')
    if not user_id or not text:
        return jsonify({'error': 'user_id ve text zorunlu'}), 400
    comment = BlogComment(user_id=user_id, blog_id=blog_id, text=text)
    db.session.add(comment)
    db.session.commit()
    return jsonify({'message': 'Yorum eklendi'}), 201


# --------------------------------------------
# ✏️ YORUM DÜZENLEME & SİLME (Admin + Restoran + Kullanıcı)
# --------------------------------------------

@app.route('/api/comments/restaurant/<int:comment_id>/delete', methods=['POST'])
def api_delete_restaurant_comment(comment_id):
    """Restoran yorumunu siler (yorum sahibi, restoran sahibi veya admin)."""
    comment = Comment.query.get_or_404(comment_id)
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id zorunlu'}), 400

    user_id = int(user_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)
    is_owner = restaurant and restaurant.owner_id == user_id
    user = User.query.get(user_id)
    is_admin = user.is_admin if user else False

    if not (comment.user_id == user_id or is_owner or is_admin):
        return jsonify({'error': 'Bu yorumu silme yetkiniz yok'}), 403

    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': 'Yorum silindi'}), 200


@app.route('/api/comments/restaurant/<int:comment_id>/edit', methods=['POST'])
def api_edit_restaurant_comment(comment_id):
    """Restoran yorumunu düzenler (yorum sahibi, restoran sahibi veya admin)."""
    comment = Comment.query.get_or_404(comment_id)
    data = request.get_json(force=True, silent=True) or {}
    user_id, new_text, new_rating = data.get('user_id'), data.get('text'), data.get('rating')
    if not all([user_id, new_text, new_rating]):
        return jsonify({'error': 'user_id, text, rating zorunlu'}), 400

    user_id = int(user_id)
    restaurant = Restaurant.query.get(comment.restaurant_id)
    is_owner = restaurant and restaurant.owner_id == user_id
    user = User.query.get(user_id)
    is_admin = user.is_admin if user else False

    if not (comment.user_id == user_id or is_owner or is_admin):
        return jsonify({'error': 'Bu yorumu düzenleme yetkiniz yok'}), 403

    comment.text = new_text
    comment.rating = int(new_rating)
    db.session.commit()
    return jsonify({'message': 'Yorum güncellendi'}), 200


@app.route('/api/comments/blog/<int:comment_id>/delete', methods=['POST'])
def api_delete_blog_comment(comment_id):
    """Blog yorumunu siler (yorum sahibi veya admin)."""
    comment = BlogComment.query.get_or_404(comment_id)
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id zorunlu'}), 400

    user_id = int(user_id)
    user = User.query.get(user_id)
    is_admin = user.is_admin if user else False
    if not (comment.user_id == user_id or is_admin):
        return jsonify({'error': 'Bu yorumu silme yetkiniz yok'}), 403

    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': 'Blog yorumu silindi'}), 200


@app.route('/api/comments/blog/<int:comment_id>/edit', methods=['POST'])
def api_edit_blog_comment(comment_id):
    """Blog yorumunu düzenler (yorum sahibi veya admin)."""
    comment = BlogComment.query.get_or_404(comment_id)
    data = request.get_json(force=True, silent=True) or {}
    user_id, new_text = data.get('user_id'), data.get('text')
    if not user_id or not new_text:
        return jsonify({'error': 'user_id ve text zorunlu'}), 400

    user_id = int(user_id)
    user = User.query.get(user_id)
    is_admin = user.is_admin if user else False
    if not (comment.user_id == user_id or is_admin):
        return jsonify({'error': 'Bu yorumu düzenleme yetkiniz yok'}), 403

    comment.text = new_text
    db.session.commit()
    return jsonify({'message': 'Blog yorumu güncellendi'}), 200



# ------------------ BAŞLAT ------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # İlk başta admin yoksa admin oluştur
        if not User.query.filter_by(email="admin@gluten.com").first():
            admin = User(email="admin@gluten.com", username="admin")
            admin.set_password("1234")
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin kullanıcı oluşturuldu.")
    with app.app_context():
        user = User.query.filter_by(email="restoranadmin@test.com").first()
        if user:
            user.confirmed = True
            db.session.commit()
            print(f"✅ {user.email} artık confirmed=True")
        else:
            print("❌ Kullanıcı bulunamadı")
    app.run(debug=True)