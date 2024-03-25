from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import random
db = SQLAlchemy()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    color = db.Column(db.String(7), nullable=False, default="#000000")  # Default color is black

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            # Log in the user
            session['user_id'] = user.id  # Store the user's ID in the session
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)  # Remove user_id from the session
    return redirect(url_for('login'))


def generate_random_color():
    # Generate a random color in hexadecimal format
    color = "#{:06x}".format(random.randint(0, 0xFFFFFF))
    return color
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    username_taken = False  # Initialize username_taken variable
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(user)  # Print user for debugging
        if user:
            flash('Username is already taken', 'error')
            username_taken = True
        else:
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match', 'error')
            else:
                new_user = User(username=form.username.data)
                new_user.set_password(form.password.data)
                new_user.color = generate_random_color() 
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
    print(form.errors)  # Print form errors for debugging
    return render_template('signup.html', form=form, username_taken=username_taken)




class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name =db.Column(db.String)
    title = db.Column(db.String, unique=True, nullable=False)
    des = db.Column(db.String)
    color=db.Column(db.String)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id =db.Column(db.Integer)
    text = db.Column(db.String, unique=True, nullable=False)
    topicId = db.Column(db.String)

with app.app_context():
    db.create_all()



from flask import session

from flask import session

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        user_id = session['user_id']
        user = User.query.get(user_id)  # Query the User table to get the user object
        if user:
            user_name = user.username  # Get the username from the user object
            user_color = user.color
            topic = Topic(
               
                user_name=user_name,  # Save the username along with the topic
                color=user_color,
                title=request.form["title"],
                des=request.form["des"]
            )
            db.session.add(topic)
            db.session.commit()

    topics = Topic.query.all()
    for topic in topics:
        print(topic.title, topic.des)
    return render_template("dashboard.html", topics=topics)





@app.route("/topic/<int:id>",methods=["GET","POST"])
def topic(id):
    if request.method == "POST":

        comment = Comment(
            # Add a new comment  
            text=request.form["text"],
            topicId=request.form["topicId"]
        )
        db.session.add(comment)
        db.session.commit()
  
    return render_template("user/detail.html")

app.run(debug=True)