from flask import Flask, render_template, redirect, url_for, flash,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import RegisterForm, LoginForm,CreatePostForm, CommentForm
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
#'8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

with app.app_context():
    #Parent
    class User(UserMixin, db.Model):
        __tablename__ = "users"
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(250), nullable=False)
        email = db.Column(db.String(250), unique= True)
        password = db.Column(db.String(250))
        posts = relationship('BlogPost', back_populates='author')
        comments = relationship('Comment', back_populates='comment_author')

    #Child_1
    class BlogPost(db.Model):
        __tablename__ = "blog_posts"
        id = db.Column(db.Integer, primary_key=True)
        #author
        author_id = db.Column(db.Integer, ForeignKey('users.id'))
        author = relationship('User', back_populates='posts')
        title = db.Column(db.String(250), unique=True, nullable=False)
        subtitle = db.Column(db.String(250), nullable=False)
        date = db.Column(db.String(250), nullable=False)
        body = db.Column(db.Text, nullable=False)
        img_url = db.Column(db.String(250))
        comments = relationship('Comment', back_populates='parent_post')

    #Child_2
    class Comment(db.Model):
        __tablename__ = 'comments'
        id = db.Column(db.Integer, primary_key=True)
        text = db.Column(db.Text, nullable=False)
        #author
        comment_author=relationship('User', back_populates='comments')
        author_id = db.Column(db.Integer, ForeignKey('users.id'))
        post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
        parent_post= relationship('BlogPost', back_populates='comments')

db.create_all()




login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#admin only decorator

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                abort(403)
            else:
                return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form= RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('User already  exists, please login ')
            return redirect(url_for('login'))
        email = form.email.data
        name = form.name.data
        password = form.password.data
        new_user = User()
        new_user.email = email
        new_user.password = generate_password_hash(password,method='pbkdf2:sha256',salt_length=8)
        new_user.name = name
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form= LoginForm()
    if form.validate_on_submit():
        login_email = form.email.data
        login_password = form.password.data

        user = User.query.filter_by(email=login_email).first()
        if not user:
            flash('Account does not exist')
            return redirect(url_for('login'))
        elif user:
            if not check_password_hash(user.password, login_password):
                flash('Invalid Password')
                return redirect(url_for('login'))
            else:
                login_user(user)

            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST','GET'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Login to comment')
            return redirect(url_for('login'))

        comment = comment_form.comment.data
        new_comment = Comment()
        new_comment.text = comment
        if current_user.is_authenticated:
            comment_author = current_user
        else:
            comment_author = None
        new_comment.comment_author = comment_author
        new_comment.parent_post = requested_post
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            author = current_user
        else:
            author = None
        new_post = BlogPost()
        new_post.title = form.title.data
        new_post.body = form.body.data
        new_post.img_url = form.img_url.data
        new_post.author = author
        new_post.subtitle = form.subtitle.data
        new_post.date = date.today().strftime("%B %d, %Y")
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, port=5006)
