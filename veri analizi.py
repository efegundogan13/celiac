import logging
from flask import request, jsonify, redirect, url_for, flash, render_template
from celiac2 import app, db, mail, s  # s: URLSafeTimedSerializer

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
                msg = Message(
                    "Glutasyon Üyeliğinizi Doğrulayın",
                    recipients=[email],
                    body=f"Merhaba! Kaydınızı tamamlamak için bu linke tıklayın:\n\n{confirm_url}"
                )
                mail.send(msg)
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
