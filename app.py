import smtplib
from turtle import title
import uuid

from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import landscape, A7
from flask_wtf.csrf import CSRFProtect, validate_csrf
from flask_login import UserMixin, current_user, login_required, LoginManager, logout_user, login_user
from sqlalchemy import ForeignKey
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from passlib.hash import sha256_crypt

# bhsgyggagqzhbmzu

app = Flask(__name__)
# Configuration de Flask-Mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'mokonan99@gmail.com'
app.config['MAIL_PASSWORD'] = 'bhsgyggagqzhbmzu'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# Clé secrète pour la sécurité des sessions
app.config['SECRET_KEY'] = 'CodeMoko'
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
# Configuration de la base de données SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Configuration de la pagination
app.config['PAGINATION_PER_PAGE'] = 5

# ========== LES MODELS ===========
    
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # champ pour l'administrateur
    voyages = db.relationship("Voyage", back_populates="client")
    billets = db.relationship('Billet', backref='owner', lazy=True)



class Voyage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ville_depart = db.Column(db.String(50), nullable=False)
    ville_arrivee = db.Column(db.String(50), nullable=False)
    date_voyage = db.Column(db.Date, nullable=False)
    heure = db.Column(db.Time, nullable=False)
    tarif = db.Column(db.Float, nullable=False)
    client_id = db.Column(db.Integer, ForeignKey('user.id'))
    client = db.relationship("User", back_populates="voyages")
    billets = db.relationship('Billet', backref='voyage', lazy=True)

    def __init__(self, ville_depart="", ville_arrivee="", date="", heure="", tarif=""):
        self.ville_depart = ville_depart
        self.ville_arrivee = ville_arrivee
        self.date_voyage = date
        self.heure = heure
        self.tarif = tarif

    def get_all(self):
        return Voyage.query.all()

    def get_by_id(self,id=id):
        return Voyage.query.filter_by(id=id).first()

    def is_exist(self):
        return Voyage.query.filter_by(ville_depart=self.ville_depart, ville_arrivee=self.ville_arrivee).all()

    def delete_by_id(self,id=id):
        voyage = Voyage.query.filter_by(id=id).first()
        if voyage:
            print("delete==",voyage.id)
            db.session.delete(voyage)
            db.session.commit()
            return True
        return False

    def insert(self):
        db.session.add(self)
        db.session.commit()
        return True

    def update(self):
        voyage = Voyage.query.filter_by(id=self.id).first()
        if voyage:
            voyage.ville_depart = self.ville_depart
            voyage.ville_arrivee = self.ville_arrivee
            voyage.date = self.date
            voyage.heure = self.heure
            voyage.tarif = self.tarif
            db.session.commit()
            return True
        return False


class Ville(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom_ville = db.Column(db.String)

    def __init__(self, nom_ville=""):
        self.nom_ville = nom_ville

    def get_all(self):
        return Ville.query.all()

    def get_by_id(self,id=id):
        return Ville.query.filter_by(id=id).first()

    def is_exist(self):
        return Ville.query.filter_by(nom_ville=self.nom_ville).first()

    def delete_by_id(self,id=id):
        ville = Ville.query.filter_by(id=id).first()
        if ville:
            db.session.delete(ville)
            db.session.commit()
            return True
        return False

    def insert(self):
        db.session.add(self)
        db.session.commit()
        return True

    def update(self):
        ville = Ville.query.filter_by(id=self.id).first()
        if ville:
            ville.nom_ville = self.nom_ville
            db.session.commit()
            return True
        return False


class Billet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voyage_id = db.Column(db.Integer, db.ForeignKey('voyage.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='reservation_user', lazy=True)
    date_reservation = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# models de contact
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(50), nullable=False)
    telephone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    sujet = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(50), nullable=False)

# Modèle de base de données pour les abonnés à la newsletter
class Abonnee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)

    def __repr__(self):
        return '<Abonné {}>'.format(self.email)

# ========== LES FORMULAIRES ===========
class RegistrationForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    email = StringField('Adresse e-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmer le mot de passe', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('S\'inscrire')


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')


class RechercheForm(FlaskForm):
    ville_depart = StringField('Ville de départ', validators=[DataRequired()])
    ville_arrivee = StringField(
        'Ville d\'arrivée', validators=[DataRequired()])
    date_voyage = DateField('Date de voyage', validators=[DataRequired()])
    heure_voyage = TimeField('Heure de départ', validators=[DataRequired()])
    submit = SubmitField('Rechercher')

class VilleForm(FlaskForm):
    ville = StringField('Nom de la ville', validators=[DataRequired()])
    submit = SubmitField('Enregistrer la ville')

class VoyageForm(FlaskForm):
    ville_depart = StringField('Ville de départ', validators=[DataRequired()])
    ville_arrivee = StringField(
        'Ville d\'arrivée', validators=[DataRequired()])
    date_voyage = DateField('Date de voyage', validators=[DataRequired()])
    heure_voyage = TimeField('Heure de départ', validators=[DataRequired()])
    tarif = IntegerField('Tarif du voyage', validators=[DataRequired()])
    submit = SubmitField('Rechercher')



# Formulaire de souscription à la newsletter
class AbonneeForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('S\'abonnée')
    
    
# Génère un code de confirmation unique
def generer_code_confirmation():
    code = str(uuid.uuid4().hex)[:8]  # Génère un code unique de 8 caractères
    return code
    
# ========== LES ROUTES ===========
@login_manager.user_loader
def load_user(user_id):
    # Récupérer l'objet utilisateur en fonction de l'ID utilisateur
    return User.query.get(user_id)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.get('/')
@app.get('/accueil')
def baseabonne():
    return render_template('accueil.html')

@app.get('/admin/')
@app.get('/admin/dashboard')
def administration():
    # recuperer les voyages et les comptes
    nombre_villes = len(Ville.query.all())
    nombre_voyages = len(Voyage.query.all())
    return render_template('admin/index.html', nombre_villes=nombre_villes, nombre_voyages=nombre_voyages)


@app.get('/apropos')
def apropos():
    return render_template('apropos.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        nom = request.form['nom']
        telephone = request.form['telephone']
        email = request.form['email']
        sujet = request.form['sujet']
        message_user = request.form['message']

        abonne = Contact(nom=nom, telephone=telephone ,email=email, sujet=sujet, message=message_user)
        db.session.add(abonne)
        db.session.commit()
        msg = Message(sujet, sender=email, recipients=['mokonan99@gmail.com','fredkesse1234@gmail.com','lebigbg0@gmail.com']) 
        msg.body = f"Mr/Mne: {nom},\n Email: {email},\n Téléphone: {telephone},\n Sujet: {sujet}, \nMessage: {message_user}"
        mail.send(msg)
        flash('Message envoyé avec succès, vous recevrez un mail...', 'success')
        return redirect(url_for('baseabonne'))
    return render_template('contact.html')

# START PARTIE_AUTHENTIFICATION
@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        # Vérification de l'administrateur
        is_admin = False
        if username == 'admin' and sha256_crypt.verify('pass', password):
            is_admin = True

        user = User(username=username, email=email, password=password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()

        flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('connexion'))
    return render_template('inscription.html', form=form)


@app.route('/connexion', methods=['GET', 'POST'])
def connexion():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and sha256_crypt.verify(password, user.password):
            login_user(user=user)
            flash('Connexion réussie !', 'success')

            if user.is_admin:
                # Rediriger vers la page d'administration
                return redirect(url_for('administration'))
            else:
                # Rediriger vers la page d'abonné
                return redirect(url_for('baseabonne'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    return render_template('connexion.html', form=form)


@app.route('/deconnexion', methods=['GET', 'POST'])
def deconnexion():
    if current_user.is_admin:
        logout_user()
        print("addmmiiinnnnnnnnnn")
        flash('Vous avez été déconnecté avec succès.', 'success')
        return redirect(url_for('connexion'))
    logout_user()
    print("auuuutttrrre")
    flash('Vous avez été déconnecté avec succès.', 'success')
    return redirect(url_for('baseabonne'))

# END PARTIE_AUTHENTIFICATION


# START PARTIE_ADMINISTRATION
@app.get("/admin/voyage")
def page_voyage():
    ville = Ville()
    return render_template("admin/voyage.html", villes=ville.get_all())


@app.get("/admin/voyages")
def page_voyages():
    voyages = Voyage()
    return render_template("admin/list_voyage.html", voyages=voyages.get_all())


@app.post("/admin/voyage")
def add_voyage():
    depart = request.form.get("ville_depart").upper().strip()
    destination = request.form.get("ville_arrivee").upper().strip()
    _date = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
    heure = datetime.strptime(request.form.get("heure"), "%H:%M").time()
    tarif = request.form.get("tarif")
    print(_date)
    if depart != destination:
        voyage = Voyage(ville_depart=depart, ville_arrivee=destination, date=_date, heure=heure, tarif=tarif)
        try:
            if voyage.insert():
                print("voyage programmé")
                flash(f"Le voyage vient d'être programmé!", "success")
        except Exception as e:
            print(f"{e} erreur")
            flash(f"{e}", "error")
    else:
        flash(
            f"Impossible de programmer un voyage de '{depart.title()}' vers '{destination.title()}'",
            "error",
        )
        print("erreur")
    return redirect(url_for("page_voyage"))

@app.route('/voyages/delete/<int:id>', methods=['GET'])
def delete_voyage(id):
    voyage = Voyage.query.get(id)
    if voyage:
        db.session.delete(voyage)
        db.session.commit()
        flash('Le voyage a été supprimé avec succès.', 'success')
    return redirect(url_for('page_voyage'))

@app.route('/voyages/update/<int:id>', methods=['GET', 'POST'])
def update_voyage(id):
    voyage = Voyage.query.get(id)
    if voyage:
        if request.method == 'POST':
            voyage.ville_depart = request.form['ville_depart']
            voyage.ville_arrivee = request.form['ville_arrivee']
            voyage.tarif = request.form['tarif']
            voyage.date_voyage = datetime.strptime(request.form.get("date_voyage"), "%Y-%m-%d").date()
            voyage.heure = datetime.strptime(request.form.get("heure"), "%H:%M").time()
            db.session.commit()
            flash('Le voyage a été mis à jour avec succès.', 'success')
            return redirect(url_for('page_voyage'))
        return render_template('admin/update_voyage.html', voyage=voyage)
    else:
        flash('Le voyage spécifié n\'existe pas.', 'error')
        return redirect(url_for('page_voyage'))


@app.get("/admin/ville")
def page_ville():
    return render_template("admin/ville.html")


@app.get("/admin/villes")
def page_villes():
    villes = Ville()
    return render_template("admin/list_ville.html", villes=villes.get_all())


@app.post("/admin/ville")
def add_ville():
    nom = request.form.get("ville").upper().strip()
    nom = nom.replace("É","E")
    ville = Ville(nom_ville=nom)
    if not ville.is_exist():
        try:
            if ville.insert():
                flash(f"La ville '{nom}' vient d'être ajoutée!", "success")
        except Exception as e:
            flash(f"{e}", "error")
    else:
        flash(f"'{nom}' existe déjà!", "error")
    return render_template("admin/ville.html")


# END PARTIE_ADMINISTRATION


@app.get("/service")
def page_verifier():
    ville = Ville()
    return render_template("service.html", villes=ville.get_all())


@app.post("/service")
def service():
    depart = request.form.get("ville_depart").upper().strip()
    destination = request.form.get("ville_arrivee").upper().strip()
    if depart != destination:
        voyage = Voyage(ville_depart=depart, ville_arrivee=destination)
        voyages = voyage.is_exist()
        if voyages:
           return render_template("resultats.html", voyages=voyages)
        else:
            flash(
            f"Aucun voyage programmé de '{depart.title()}' vers '{destination.title()}'",
            "warning",
        )
    else:
        flash(
            f"Impossible de programmer un voyage de '{depart.title()}' vers '{destination.title()}'",
            "error",
        )
    return redirect(url_for("page_verifier"))



@app.route('/voyages')
def afficher_voyages():
    voyages = Voyage.query.order_by(Voyage.date_voyage.desc()).all()[:7]
    return render_template('voyages.html', voyages=voyages)

@app.route('/confirmation', methods=['GET', 'POST'])
def page_confirmation():
    return render_template('confirmation.html', code_confirmation=code_confirmation)


code_confirmation = generer_code_confirmation()

@app.route('/confirmation', methods=['POST'])
def confirmation_reserve():
    code_saisi = request.form['code_confirmation']
    # Récupérer le code de confirmation associé à la réservation depuis la base de données

    if code_saisi == code_confirmation:
        # Confirmer la réservation
        flash("Votre réservation a été confirmée avec succès.", 'success')
        return redirect(url_for('baseabonne'))
    else:
        # Afficher un message d'erreur si le code de confirmation est incorrect
        flash("Le code de confirmation saisi est incorrect. Veuillez réessayer.", 'danger')
        return redirect(url_for('page_confirmation'))


@app.route('/reservation/<int:voyage_id>', methods=['GET', 'POST'])
@login_required
def reservation(voyage_id):
    voyage = Voyage.query.get_or_404(voyage_id)
    form = VoyageForm()
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter pour effectuer une réservation.', 'warning')
        return redirect(url_for('connexion'))

    reservation_existante = Billet.query.filter_by(
        voyage_id=voyage_id, user_id=current_user.id).first()
    user = User.query.get(current_user.id)
    if reservation_existante:
        flash('Vous avez déjà réservé un billet pour ce voyage.', 'info')
        return redirect(url_for('baseabonne'))

    if request.method == 'POST':
        billet = Billet(voyage_id=voyage_id, user_id=current_user.id)
        db.session.add(billet)
        db.session.commit()
        flash('Réservation effectuée avec succès !', 'success')
        return redirect(url_for('baseabonne'))

    return render_template('reservation.html', voyage=voyage, form=form, user=user)

def get_voyage_by_id(voyage_id): 
    voyage = Voyage.query.get(voyage_id)
    return voyage

@app.route('/reservation/recu/<int:voyage_id>', methods=['POST','GET'])
def show_recu(voyage_id):
    voyage = get_voyage_by_id(voyage_id)
    return render_template('reservation.html', voyage=voyage)

@app.route('/reservation/pdf/<int:voyage_id>', methods=['POST','GET'])
def generate_pdf_ticket(voyage_id):
    if not current_user.is_authenticated:
        return redirect(url_for('connexion'))
    
    voyage = get_voyage_by_id(voyage_id)
    # recuperer l'utilisateur connecté
    user = User.query.get(current_user.id)
    if voyage:
        # Créer le document PDF avec la taille de page spécifiée
        pdf = canvas.Canvas("ticket_reservation.pdf", pagesize=landscape((410,230)))

        # Modifier la taille et la police pour s'adapter à un format de ticket plus petit
        pdf.setFont("Helvetica-Bold", 12)

        # Centrer le titre
        pdf.drawCentredString(205, 200, "Moko.Car - Ticket de réservation")

        # Informations sur le voyage à gauche
        pdf.drawString(10, 160, f"Départ : {voyage.ville_depart}")
        pdf.drawString(10, 140, f"Destination : {voyage.ville_arrivee}")
        pdf.drawString(10, 120, f"Tarif : {voyage.tarif} FCFA")
        pdf.drawString(10, 100, f"Date : {voyage.date_voyage.strftime('%d-%m-%Y')}")
        pdf.drawString(10, 80, f"Heure : {voyage.heure.strftime('%H:%M')}")

        # Informations sur l'utilisateur à droite
        pdf.drawString(210, 160, f"Nom utilisateur : {user.username}")
        pdf.drawString(210, 140, f"E-mail : {user.email}")

        # Centrer "Bon voyage!" en bas
        pdf.drawCentredString(205, 40, "Bon voyage!")

        # Dessiner un cadre autour du contenu
        pdf.rect(5, 35, 400, 185)
        
        # Sauvegarder le PDF généré
        pdf.save()

        # Créer une réponse Flask avec le fichier PDF généré
        response = make_response(open("ticket_reservation.pdf", "rb").read())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=ticket_reservation.pdf'
        return response

    else:
        flash("Voyage non trouvé", "danger")
        return redirect(url_for('reservation_disponible'))



@app.route('/annuler_reservation/<int:billet_id>', methods=['POST'])
@login_required
def annuler_reservation(billet_id):
    billet = Billet.query.get_or_404(billet_id)

    if not current_user.is_authenticated:
        flash('Veuillez vous connecter pour annuler une réservation.', 'warning')
        return redirect(url_for('connexion'))

    if billet.user != current_user.id:
        flash('Vous n\'êtes pas autorisé à annuler cette réservation.', 'warning')
        return redirect(url_for('baseabonne'))

    # Vérifier le jeton CSRF
    form = FlaskForm()
    try:
        validate_csrf(form.csrf_token.data)
    except:
        flash('Échec de la validation du jeton CSRF.', 'danger')
        return redirect(url_for('baseabonne'))

    db.session.delete(billet)
    db.session.commit()

    flash('Réservation annulée avec succès.', 'success')
    return redirect(url_for('baseabonne'))


@app.route('/historique-voyages/<int:client_id>')
def historique_voyages_client(client_id):
    # Récupérer le client spécifique ou afficher une erreur 404 si introuvable
    client = User.query.get_or_404(client_id)

    # Récupérer tous les billets associés à ce client
    billets = Billet.query.filter_by(user_id=client_id).order_by(Billet.date_reservation.desc()).all()
    print('bbb',billets)

    return render_template('historique_voyages_client.html', client=client, billets=billets)

if __name__ == '__main__':
    app.run(debug=True)
