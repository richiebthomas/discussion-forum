from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify


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
    user_id = db.Column(db.Integer)
    title = db.Column(db.String, unique=True, nullable=False)
    des = db.Column(db.String)
    color=db.Column(db.String)

from sqlalchemy.orm import relationship

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    user_name = db.Column(db.String)
    text = db.Column(db.String, nullable=False)
    topicId = db.Column(db.String)
    color = db.Column(db.String)
    
    # Relationship with itself (one-to-many)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    replies = relationship('Comment', backref=db.backref('parent', remote_side=[id]))


with app.app_context():
    db.create_all()



from flask import session

from flask import session

@app.route("/", methods=["GET", "POST"])
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
                user_id=user_id,
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





@app.route("/topic/<int:id>", methods=["GET", "POST"])
def topic(id):
    topic = Topic.query.get_or_404(id)
    if request.method == "POST":
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            user_name = user.username
            color = user.color
            parent_id = request.form.get("parent_id")  # Get the parent comment ID
            if parent_id:  # If it's a reply to a comment
                parent_comment = Comment.query.get(parent_id)
                if parent_comment:
                    comment = Comment(
                        text=request.form["text"],
                        topicId=id,
                        user_id=user_id,
                        color=color,
                        user_name=user_name,
                        parent_id=parent_id  # Set the parent comment ID
                    )
                    db.session.add(comment)
                    db.session.commit()
            else:  # If it's a new comment
                comment = Comment(
                    text=request.form["text"],
                    topicId=id,
                    user_id=user_id,
                    color=color,
                    user_name=user_name
                )
                db.session.add(comment)
                db.session.commit()
    user_id = session['user_id']
    comments = Comment.query.filter_by(topicId=id, parent_id=None).all()  # Fetch top-level comments only
    return render_template("topic.html", topic=topic, comments=comments, user_id=user_id)

@app.route("/reply/<int:id>", methods=["POST"])
def reply(id):
    if 'user_id' not in session:
        flash('You need to be logged in to reply to comments.', 'error')
        return redirect(url_for('login'))
    
    # Get the user ID of the logged-in user
    user_id = session['user_id']

    # Check if the comment being replied to exists
    parent_comment = Comment.query.get(id)
    if not parent_comment:
        flash('Comment not found.', 'error')
        return redirect(url_for('dashboard'))  # Redirect to dashboard or topic page

    # Get the text of the reply from the form submission
    reply_text = request.form.get('replyText')

    # If the parent comment is not a root comment, modify the reply text
    if parent_comment.parent_id:
        parent_user = User.query.get(parent_comment.user_id)
        if parent_user:
            parent_user_name = parent_user.username
            reply_text = f"@{parent_user_name} {reply_text}"

    # Create a new comment object for the reply
    user = User.query.get(user_id)
    if user:
        user_name = user.username
        color = user.color
    reply = Comment(
        text=reply_text,
        user_id=user_id,
        user_name=user_name,  # Assuming you store the username in the session
        topicId=parent_comment.topicId,
        color=color,  # Set the color as needed
        parent_id=parent_comment.id  # Set the parent comment ID
    )

    # Add the reply to the database session and commit
    db.session.add(reply)
    db.session.commit()

    flash('Your reply has been added successfully.', 'success')
    return redirect(url_for('topic', id=parent_comment.topicId))

@app.route("/delete_topic/<int:id>", methods=["POST"])
def delete_topic(id):
    # Retrieve the topic by its ID
    topic = Topic.query.get_or_404(id)
    
    # Check if the current user is authorized to delete the topic
    if topic.user_id == session.get('user_id'):
        # Delete the topic from the database
        db.session.delete(topic)
        db.session.commit()
        flash('Topic deleted successfully.', 'success')
    else:
        flash('You are not authorized to delete this topic.', 'error')
    
    # Redirect back to the page where the topic was displayed
    return redirect(url_for('dashboard'))

@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    # Assuming you have a Comment model and can query the comment by its ID
    comment = Comment.query.get(comment_id)
    if comment:
        # Assuming you have logic to check if the user is authorized to delete the comment
        if comment.user_id == session.get('user_id'):
            # Delete the comment from the database
            db.session.delete(comment)
            db.session.commit()
            flash('Comment deleted successfully.', 'success')
        else:
            flash('You are not authorized to delete this comment.', 'error')
    else:
        flash('Comment not found.', 'error')
    return redirect(request.referrer)

# Route to delete a reply
@app.route("/delete_reply/<int:comment_id>", methods=["POST"])
def delete_reply(comment_id):  # Changed the function name to delete_reply
    # Assuming you have a Comment model and can query the comment by its ID
    comment = Comment.query.get(comment_id)
    if comment:
        # Assuming you have logic to check if the user is authorized to delete the comment
        if comment.user_id == session.get('user_id'):
            # Delete the comment and its associated replies from the database
            db.session.delete(comment)
            # Delete associated replies
            associated_replies = Comment.query.filter_by(parent_id=comment_id).all()
            for reply in associated_replies:
                db.session.delete(reply)
            db.session.commit()
            flash('Comment and associated replies deleted successfully.', 'success')
        else:
            flash('You are not authorized to delete this comment.', 'error')
    else:
        flash('Comment not found.', 'error')
    return redirect(request.referrer)



app.run(host='0.0.0.0', port=8000)
#app.run(debug="true")