from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
# Flask: Flask uygulamasını başlatır.
# render_template: HTML şablon dosyalarını(.html) render etmek için kullanılır. render_template("index.html") vs.
# request: HTTP isteği (GET, POST vs.) ile gönderilen verilere erişmek için kullanılır.
# redirect: Belirli bir url'ye yönlendirme yapmak için kullanılır. redirect(url_for("login"))
# url_for: Bir route fonskiyonunun URL'sini dinamik olarak oluşturur.url_for("home")
# flash: Kullanıcıya tek seferlik bilgi veya hata mesajı vermek için kullanılır. flash("Kayıt Başarılı") vs.
# session: Kullanıcı oturum bilgilerini saklamak için kullanılır. session["user_id"] = 3 vs.
from flask_sqlalchemy import SQLAlchemy
# Veritabanı işlemlerini Python'ın sınıfları üzerinden yapmayı sağlar.
from werkzeug.security import generate_password_hash, check_password_hash
# generate_password_hash: Parolayı hash'leyerek veritabanına güvenli bir şekilde kaydeder.
# check_password_hash: Kullanıcının girdiği şifrenin hashlenmiş versiyonla eşleşip eşleşmediğini kontrol eder.
import os
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__) # Flask uygulamasını başlatır.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get("SECRET_KEY", "fallback_key")

db = SQLAlchemy(app)

# ------------------ MODELLER ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

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
    description = db.Column(db.Text)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

    products = db.relationship('Product', backref='restaurant', lazy=True)

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

    user = db.relationship('User', backref='comments')
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


# BLOG MODELLERİ

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

    # İlişkiler
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


# TARİF MODELLERİ

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='recipes')

# ------------------ ROUTELAR ------------------

@app.route('/')
def index():
    return render_template('index.html')

# -------------- Giriş / Kayıt / Çıkış --------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash("Bu e-posta zaten kayıtlı.", "danger")
            return redirect(url_for('register'))

        user = User(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash(f"Hoş geldin {user.username}!", "success")
            return redirect(url_for('index'))
        else:
            flash("E-posta veya şifre hatalı.", "danger")

    return render_template('login.html')

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

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            return jsonify({'message': 'Giriş başarılı!', 'user_id': user.id}), 200
        else:
            return jsonify({'error': 'Giriş başarısız!'}), 401

    except Exception as e:
        print(f"Hata: {e}")
        return jsonify({'error': 'Sunucu hatası'}), 500


@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('index'))

# -------------- Restoranlar --------------

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

    # Şehir ve kategoriler listesi
    cities = db.session.query(Restaurant.city).distinct().all()
    categories = db.session.query(Restaurant.category).distinct().all()

    return render_template('restaurants.html',
                           restaurants=restaurants,
                           cities=cities,
                           categories=categories,
                           selected_city=selected_city)  # 💥 Şehri şablona da yolluyoruz



@app.route('/restaurants/<int:id>')
def restaurant_detail(id):
    restaurant = Restaurant.query.get_or_404(id)
    products = Product.query.filter_by(restaurant_id=id).all()
    return render_template('restaurant_detail.html', restaurant=restaurant, products=products)

# -------------- Admin: Restoran Yönetimi --------------

@app.route('/admin/add-restaurant', methods=['GET', 'POST'])
def add_restaurant():
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_restaurant = Restaurant(
            name=request.form['name'],
            address=request.form['address'],
            city=request.form['city'],
            category=request.form['category'],
            image_url=request.form['image_url'],
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
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    restaurant = Restaurant.query.get_or_404(id)
    if request.method == 'POST':
        restaurant.name = request.form['name']
        restaurant.address = request.form['address']
        restaurant.city = request.form['city']
        restaurant.category = request.form['category']
        restaurant.image_url = request.form['image_url']
        restaurant.description = request.form['description']
        restaurant.latitude = request.form.get('latitude', type=float)
        restaurant.longitude = request.form.get('longitude', type=float)
        db.session.commit()
        flash("Restoran güncellendi.", "success")
        return redirect(url_for('restaurants'))

    return render_template('admin/edit_restaurant.html', restaurant=restaurant)

@app.route('/admin/delete-restaurant/<int:id>', methods=['POST'])
def delete_restaurant(id):
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    restaurant = Restaurant.query.get_or_404(id)
    db.session.delete(restaurant)
    db.session.commit()
    flash("Restoran silindi.", "success")
    return redirect(url_for('restaurants'))

# -------------- Admin: Ürün Yönetimi --------------

@app.route('/admin/add-product', methods=['GET', 'POST'])
def add_product():
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    restaurants = Restaurant.query.all()

    if request.method == 'POST':
        new_product = Product(
            name=request.form['name'],
            category=request.form['category'],
            description=request.form['description'],
            image_url=request.form['image_url'],
            restaurant_id=request.form['restaurant_id']
        )
        db.session.add(new_product)
        db.session.commit()
        flash("Ürün eklendi.", "success")
        return redirect(url_for('restaurants'))

    return render_template('admin/add_product.html', restaurants=restaurants)


@app.route('/admin/edit-product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        # Sadece bu alanları güncelliyoruz
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

        return redirect(url_for('products'))

    return render_template('admin/edit_product.html', product=product)


@app.route('/admin/delete-product/<int:id>', methods=['POST'])
def delete_product(id):
    if not session.get('is_admin'):
        flash("Yetkiniz yok.", "danger")
        return redirect(url_for('login'))

    product = Product.query.get_or_404(id)

    # Önce bu ürüne bağlı favori kayıtlarını sil
    FavoriteProduct.query.filter_by(product_id=product.id).delete()

    # Sonra ürünü sil
    db.session.delete(product)
    db.session.commit()

    flash("Ürün ve ilişkili favori kayıtları başarıyla silindi.", "success")
    return redirect(url_for('products'))

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


# Ürün Detay Sayfası
@app.route('/products/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    comments = ProductComment.query.filter_by(product_id=product_id).all()
    return render_template('product_detail.html', product=product, comments=comments)

# Ürün Yorum Ekle
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

# Ürün Yorum Sil
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


# ------------------ FAVORİ RESTORAN ------------------

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

# ------------------ FAVORİ ÜRÜN ------------------

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
    user_comments = Comment.query.filter_by(user_id=user_id).all()

    return render_template(
        'profile.html',
        favorite_restaurants=favorite_restaurants,
        favorite_products=favorite_products,
        user_comments=user_comments
    )


@app.route('/restaurants/<int:restaurant_id>/comment', methods=['POST'])
def add_comment(restaurant_id):
    if not session.get('user_id'):
        flash("Yorum yapabilmek için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    text = request.form['text']
    rating = request.form['rating']

    if not rating or not text:
        flash("Yorum ve puan boş bırakılamaz.", "danger")
        return redirect(url_for('restaurant_detail', id=restaurant_id))


    new_comment = Comment(
        user_id=session['user_id'],
        restaurant_id=restaurant_id,
        rating=int(rating),
        text=text
    )
    db.session.add(new_comment)
    db.session.commit()

    flash("Yorum başarıyla eklendi!", "success")
    return redirect(url_for('restaurant_detail', id=restaurant_id))


@app.route('/search')
def search():
    query = request.args.get('q', '')

    # Restoran adı arama
    restaurants = Restaurant.query.filter(Restaurant.name.ilike(f"%{query}%")).all()

    # Ürün adı arama
    products = Product.query.filter(Product.name.ilike(f"%{query}%")).all()

    return render_template('search_results.html', query=query, restaurants=restaurants, products=products)

@app.route('/delete-comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if not session.get('user_id'):
        flash("İşlem için giriş yapmalısın.", "danger")
        return redirect(url_for('login'))

    comment = Comment.query.get_or_404(comment_id)

    if comment.user_id != session['user_id']:
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

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Bu sayfayı görüntülemek için yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    user_count = User.query.count()
    restaurant_count = Restaurant.query.count()
    product_count = Product.query.count()
    comment_count = Comment.query.count()

    return render_template('admin_dashboard.html',
                           user_count=user_count,
                           restaurant_count=restaurant_count,
                           product_count=product_count,
                           comment_count=comment_count)

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

    # Dropdown için mevcut kategoriler
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

        # Mesafeye göre sırala
        nearby_restaurants.sort(key=lambda x: x[1])

        # En yakın 5 restoran
        top_5 = nearby_restaurants[:5]

        return render_template('nearby.html', top_5=top_5)

    return render_template('nearby.html', top_5=[])


import math

def haversine(lat1, lon1, lat2, lon2):
    R = 6371  # Dünya'nın yarıçapı km cinsinden
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

    # Sadece yorum sahibi veya admin silebilir
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

    # Sadece yorum sahibi veya admin düzenleyebilir
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

    # Önce yorumları sil
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

"""
MOBİL
"""

@app.route('/api/restaurants')
def api_restaurants():
    restaurants = Restaurant.query.all()
    return jsonify([
        {
            'id': r.id,
            'name': r.name,
            'description': r.description,
            'city': r.city,
            'district': '',  # Eğer varsa: r.district
            'image_url': r.image_url,
            'latitude': r.latitude,
            'longitude': r.longitude
        }
        for r in restaurants
    ])


@app.route('/api/restaurants/<int:restaurant_id>/products')
def api_restaurant_products(restaurant_id):
    products = Product.query.filter_by(restaurant_id=restaurant_id).all()
    data = [
        {
            'id': p.id,
            'name': p.name,
            'category': p.category,
            'description': p.description,
            'image_url': p.image_url,
            'restaurant_id': p.restaurant_id
        }
        for p in products
    ]
    return jsonify(data)

@app.route('/api/nearby', methods=['POST'])
def api_nearby():
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

    return jsonify([
        {
            'id': r.id,
            'name': r.name,
            'image_url': r.image_url,
            'city': r.city,
            'district': getattr(r, 'district', ''),
            'address': r.address,
            'distance_km': round(d, 2)
        } for r, d in top_5
    ])


@app.route('/api/products')
def api_products():
    restaurant_id = request.args.get('restaurant_id')

    if restaurant_id:
        products = Product.query.filter_by(restaurant_id=restaurant_id).all()
    else:
        products = Product.query.all()

    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'description': p.description,
            'ingredients': p.description,  # içerik bilgisi yoksa açıklamayı kullan
            'image_url': p.image_url,
            'restaurant_id': p.restaurant_id
        } for p in products
    ])



@app.route('/api/recipes')
def api_recipes():
    recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    data = [
        {
            'id': r.id,
            'title': r.title,
            'content': r.content,
            'image_url': r.image_url,
            'user_id': r.user_id
        }
        for r in recipes
    ]
    return jsonify(data)

@app.route('/api/comments/restaurant', methods=['POST'])
def api_comment_restaurant():
    data = request.json
    user_id = data.get('user_id')
    restaurant_id = data.get('restaurant_id')
    rating = data.get('rating')
    text = data.get('text')

    new_comment = Comment(
        user_id=user_id,
        restaurant_id=restaurant_id,
        rating=rating,
        text=text
    )
    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': 'Yorum başarıyla eklendi'})

@app.route('/api/comments/product', methods=['POST'])
def api_comment_product():
    data = request.json
    user_id = data.get('user_id')
    product_id = data.get('product_id')
    rating = data.get('rating')
    text = data.get('text')

    new_comment = ProductComment(
        user_id=user_id,
        product_id=product_id,
        rating=rating,
        text=text
    )
    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': 'Yorum başarıyla eklendi'})

recipe_like_store = {}

@app.route('/api/like/recipe', methods=['POST'])
def api_like_recipe():
    data = request.json
    recipe_id = str(data.get('recipe_id'))
    user_id = str(data.get('user_id'))

    key = f"{recipe_id}-{user_id}"
    if key in recipe_like_store:
        del recipe_like_store[key]
        return jsonify({'liked': False})
    else:
        recipe_like_store[key] = True
        return jsonify({'liked': True})

@app.route('/api/user/favorites/<int:user_id>')
def api_user_favorites(user_id):
    fav_restaurants = FavoriteRestaurant.query.filter_by(user_id=user_id).all()
    fav_products = FavoriteProduct.query.filter_by(user_id=user_id).all()

    return jsonify({
        'restaurants': [f.restaurant_id for f in fav_restaurants],
        'products': [f.product_id for f in fav_products]
    })

@app.route('/api/user/comments/<int:user_id>')
def api_user_comments(user_id):
    rest_comments = Comment.query.filter_by(user_id=user_id).all()
    prod_comments = ProductComment.query.filter_by(user_id=user_id).all()

    return jsonify({
        'restaurant_comments': [{'text': c.text, 'restaurant_id': c.restaurant_id} for c in rest_comments],
        'product_comments': [{'text': c.text, 'product_id': c.product_id} for c in prod_comments]
    })

@app.route('/api/user/<int:user_id>/profile')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)

    fav_restaurants = FavoriteRestaurant.query.filter_by(user_id=user_id).all()
    fav_products = FavoriteProduct.query.filter_by(user_id=user_id).all()
    comments = Comment.query.filter_by(user_id=user_id).all()

    return jsonify({
        'username': user.username,
        'favorites': {
            'restaurants': [r.restaurant.name for r in fav_restaurants],
            'products': [p.product.name for p in fav_products]
        },
        'comments': [
            {
                'restaurant': c.restaurant.name,
                'text': c.text,
                'rating': c.rating
            } for c in comments
        ]
    })

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '').strip().lower()

    if not query:
        return jsonify({
            'restaurants': [],
            'products': [],
            'recipes': []
        })

    restaurants = Restaurant.query.filter(Restaurant.name.ilike(f'%{query}%')).all()
    products = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    recipes = Recipe.query.filter(Recipe.title.ilike(f'%{query}%')).all()

    return jsonify({
        'restaurants': [
            {
                'id': r.id,
                'name': r.name,
                'description': r.description,
                'city': r.city,
                'image_url': r.image_url,
                'latitude': r.latitude,
                'longitude': r.longitude
            } for r in restaurants
        ],
        'products': [
            {
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'restaurant_id': p.restaurant_id
            } for p in products
        ],
        'recipes': [
            {
                'id': rec.id,
                'title': rec.title,
                'content': rec.content,
                'image_url': rec.image_url
            } for rec in recipes
        ]
    })

@app.route('/api/blogs')
def api_blogs():
    blogs = Blog.query.order_by(Blog.created_at.desc()).all()
    blog_list = [
        {
            'id': blog.id,
            'title': blog.title,
            'content': blog.content,
            'image_url': blog.image_url,
            'created_at': blog.created_at.strftime('%Y-%m-%d'),
            'category': blog.category.name if blog.category else None
        }
        for blog in blogs
    ]
    return jsonify(blog_list)

@app.route('/api/blogs/<int:id>')
def api_blog_detail(id):
    blog = Blog.query.get_or_404(id)
    return jsonify({
        'id': blog.id,
        'title': blog.title,
        'content': blog.content,
        'image_url': blog.image_url,
        'created_at': blog.created_at.strftime('%Y-%m-%d'),
        'category': blog.category.name if blog.category else None
    })

@app.route('/api/blogs/category/<int:category_id>')
def api_blogs_by_category(category_id):
    blogs = Blog.query.filter_by(category_id=category_id).order_by(Blog.created_at.desc()).all()
    result = []

    for blog in blogs:
        result.append({
            'id': blog.id,
            'title': blog.title,
            'content': blog.content,
            'image_url': blog.image_url,
            'created_at': blog.created_at.strftime('%Y-%m-%d'),
            'category': blog.category.name if blog.category else None
        })

    return jsonify(result)

@app.route('/api/blogs/<int:blog_id>/comments')
def api_blog_comments(blog_id):
    comments = BlogComment.query.filter_by(blog_id=blog_id).order_by(BlogComment.created_at.desc()).all()
    result = []

    for c in comments:
        result.append({
            'id': c.id,
            'text': c.text,
            'created_at': c.created_at.strftime('%Y-%m-%d'),
            'username': c.user.username if c.user else 'Anonim'
        })

    return jsonify(result)

@app.route('/api/blogs/<int:blog_id>/comment', methods=['POST'])
def api_add_blog_comment(blog_id):
    data = request.get_json()

    user_id = data.get('user_id')
    text = data.get('text')

    if not user_id or not text:
        return jsonify({'error': 'user_id ve text zorunlu'}), 400

    comment = BlogComment(user_id=user_id, blog_id=blog_id, text=text)
    db.session.add(comment)
    db.session.commit()

    return jsonify({'message': 'Yorum eklendi'}), 201


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

    app.run(debug=True)

