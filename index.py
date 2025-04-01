from flask import Flask, abort, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('stories', lazy=True))
    image_file = db.Column(db.String(120), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_admin():
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            hashed_pw = bcrypt.generate_password_hash("adminpassword").decode("utf-8")
            admin_user = User(username="Admin", password=hashed_pw, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")

@app.route('/')
def home():
    stories = Story.query.all()
    return render_template('home.html', stories=stories, user_authenticated=current_user.is_authenticated)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('User already exists, please log in.', 'error')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash('Invalid credentials. Please try again.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for("home"))

    users = User.query.all()
    stories = Story.query.all()
    return render_template("admin_dashboard.html", users=users, stories=stories)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/create_story', methods=['GET', 'POST'])
@login_required
def create_story():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image = request.files.get('image')
        image_filename = None

        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_story = Story(title=title, content=content, user_id=current_user.id, image_file=image_filename)
        db.session.add(new_story)
        db.session.commit()

        flash('Story created successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('create_story.html')

@app.route('/story/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    story = Story.query.get_or_404(story_id)
    if story.user_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        story.title = request.form['title']
        story.content = request.form['content']
        db.session.commit()
        flash('Story updated successfully!', 'success')
        return redirect(url_for('view_story', story_id=story.id))

    return render_template('edit_story.html', story=story)

@app.route('/delete_story/<int:story_id>', methods=['POST'])
@login_required
def delete_story(story_id):
    story = Story.query.get_or_404(story_id)

    if current_user.id != story.user_id and not current_user.is_admin:
        flash('You do not have permission to delete this story.', 'danger')
        return redirect(url_for('view_story', story_id=story_id))

    db.session.delete(story)
    db.session.commit()
    flash('Story deleted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("You don't have permission to delete users.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't delete yourself!", "warning")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/story/<int:story_id>')
def view_story(story_id):
    story = Story.query.get_or_404(story_id)
    return render_template('view_story.html', story=story)

if __name__ == '__main__':
    create_admin()
    app.run(debug=True)
