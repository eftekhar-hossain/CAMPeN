from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pandas as pd
import ast,re
from get_highlighted import get_overlap_narratives, get_conflict_narratives, get_unique_narratives
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from extensions import db, bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf.csrf import CSRFProtect
from collections import defaultdict



app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key for sessions
# link app to database.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'testingKey' # Replace with a secure key for production
db.init_app(app)
bcrypt.init_app(app)
csrf = CSRFProtect(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Sample data
# a_list = ["How Are You", "I am fine"]
# b_list = ["What is your name", "My name is"]
# elem = {"n1": a_list, "n2": b_list}
def clean_text(text):
    return re.sub(r'\s+', ' ', re.sub(r"[\"“”:']", "", text)).strip()

data = pd.read_excel("annotation_oct18.xlsx")

all_narrative_1 = data['Review1'].tolist()
all_narrative_1 = [clean_text(text) for text in all_narrative_1]
all_narrative_2 = data['Review2'].tolist()
all_narrative_2 = [clean_text(text) for text in all_narrative_2]
elem = {"n1": all_narrative_1, "n2": all_narrative_2}
overlap = data['is_overlap'].tolist()
conflict = data['is_conflict'].tolist()
unique1 = data['is_unique_n1'].tolist()
unique2 = data['is_unique_n2'].tolist()


# Define the cleaning function


# Initialize the current index
current_index = 0



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    isAdmin = db.Column(db.Boolean, default=False) # Admin privilege

class registerForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existingUserUsername = User.query.filter_by(
            username=username.data).first()
        
        if existingUserUsername:
            raise ValidationError("That username already exists, Please choose a different one.")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Login")

class UserResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Auto-incrementing ID
    custom_id = db.Column(db.String, nullable=True, unique=True)  # Custom identifier
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clause_id = db.Column(db.String, nullable=False)
    clause_type = db.Column(db.String, nullable=False)  # This is your category
    choice = db.Column(db.String, nullable=False)  # agree, disagree, neutral
    narrative_index = db.Column(db.Integer, nullable=False)

    

# Login System
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerForm()
    
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.password.data)
        newUser = User(username=form.username.data, password=hashedPassword)
        db.session.add(newUser)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# below shows current directory of users
@app.route('/admin')
@login_required 
def show_db_contents():
    if not current_user.isAdmin: # Check if user has admin privilege
        return "Access denied", 403
    
    users = User.query.all()
    return "<br>".join([f"ID: {user.id}, Username: {user.username}" for user in users])

@app.route('/admin/database', methods=['GET'])
@login_required
def admin_database_view():
    if not current_user.isAdmin:  # Ensure only admins can view this page
        return "Access Denied", 403

    # Query all user responses from the database
    responses = UserResponse.query.all()

    # Prepare data to send to the template
    response_data = [
        {
            'id': response.id,
            'user_id': response.user_id,
            'clause_id': response.clause_id,
            'clause_type': response.clause_type,
            'choice': response.choice,
            'narrative_index': response.narrative_index
        }
        for response in responses
    ]

    return render_template('admin_database.html', responses=response_data)

@app.route('/clear_responses', methods=['POST'])
@login_required
def clear_responses():
    data = request.get_json()
    user_id = current_user.id
    clause_id = data['clause_id']
    clause_type = data['clause_type']
    narrative_index = session.get('current_index', 0)

    # Query the database to find matching entries and delete them
    UserResponse.query.filter_by(
        user_id=user_id,
        clause_id=clause_id,
        clause_type=clause_type,
        narrative_index=narrative_index
    ).delete()

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Responses cleared successfully'})





@app.route('/record_response', methods=['POST'])
@login_required
def record_response():
    data = request.get_json()
    clause_id = data['clause_id']
    clause_type = data['clause_type']
    choice = data['choice']
    user_id = current_user.id
    

    narrative_index = session.get('current_index', 0)

    #custom identifier
    custom_id = f"{user_id}-{narrative_index}-{clause_id}-{clause_type}"

    # check if a response already exists for the user, clause, and narrative index
    existing_response = UserResponse.query.filter_by(custom_id=custom_id).first()


    if existing_response:
        #update the existing response
        existing_response.choice = choice
    else:
        
        # create new response
        response = UserResponse(
            user_id=user_id,
            clause_id=clause_id,
            clause_type=clause_type,
            choice=choice,
            narrative_index=narrative_index,
            custom_id=custom_id
        )
        db.session.add(response)

    db.session.commit()

    return jsonify({'status': 'success'})

@app.route('/delete_response', methods=['DELETE'])
@login_required
def delete_response():
    data = request.get_json()
    clause_id = data['clause_id']
    clause_type = data['clause_type']
    user_id = current_user.id

    narrative_index = session.get('current_index', 0)

    #Find the existing response
    existing_response = UserResponse.query.filter_by(
        user_id=user_id,
        clause_id=clause_id,
        clause_type=clause_type,
        narrative_index=narrative_index
    ).first()

    if existing_response:
        db.session.delete(existing_response)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Response deleted'})
    else: 
        return jsonify({'status': 'error', 'message': 'Response not found'}), 404

@app.route('/index')
@login_required
def index():
    # Retrieve current index from session
    current_index = session.get('current_index', 0)
    # Retrieve toggle states from session
    show_overlap = session.get('show_overlap', False)
    show_conflict = session.get('show_conflict', False)
    show_unique1 = session.get('show_unique1', False)
    show_unique2 = session.get('show_unique2', False)

    narrative1 = all_narrative_1[current_index]
    narrative2 = all_narrative_2[current_index]

    # Parse data once
    overlap_raw = ast.literal_eval(overlap[current_index])
    conflict_raw = ast.literal_eval(conflict[current_index])
    unique1_raw = ast.literal_eval(unique1[current_index])
    unique2_raw = ast.literal_eval(unique2[current_index])

    # Clean and prepare data
    overlap_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                      'sentence_2': clean_text(item['sentence_2'])} 
                     for item in overlap_raw]

    conflict_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                       'sentence_2': clean_text(item['sentence_2'])} 
                      for item in conflict_raw]

    unique1_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                      'sentence_2': item['sentence_2']} 
                     for item in unique1_raw]

    unique2_batch = [{'sentence_1': item['sentence_1'], 
                      'sentence_2': clean_text(item['sentence_2'])} 
                     for item in unique2_raw]
    
    responses = UserResponse.query.filter_by(
        user_id=current_user.id,
        narrative_index=current_index
    ).all()

    responses_by_category = defaultdict(list)
    for response in responses:
        responses_by_category[response.clause_type].append(response)

    saved_responses_dict = {f"{resp.clause_id}_{resp.clause_type}": resp.choice for resp in responses}

    # Render the template with the prepared data
    return render_template('index.html', 
                       file=elem, 
                       current_index=current_index, 
                       overlap=overlap_batch if show_overlap else [],
                       conflict=conflict_batch if show_conflict else [],
                       unique1=unique1_batch if show_unique1 else [],
                       unique2=unique2_batch if show_unique2 else [],
                       show_overlap=show_overlap, 
                       show_conflict=show_conflict,
                       show_unique1=show_unique1, 
                       show_unique2=show_unique2,
                       responses_by_category=responses_by_category)


@app.route('/next')
@login_required
def next_narrative():

    # if we want that after pressing the next button clause button reset
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False

    # get the current index from the session
    current_index = session.get('current_index', 0)
    
    # Increment index but keep it within the bounds
    if current_index < len(elem['n1']) - 1:
        current_index += 1
    session['current_index'] = current_index # this stores updated index in the session
    return redirect(url_for('index'))

@app.route('/prev')
@login_required
def prev_narrative():
    # if we want that after pressing the prev button clause button reset
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
   
    # get current index from session
    current_index = session.get('current_index', 0) 
    # Decrement index but keep it within the bounds
    if current_index > 0:
        current_index -= 1
    session['current_index'] = current_index
    return redirect(url_for('index'))

@app.route('/overlap_action')
def overlap_action():

    # Toggle the show_overlap state in the session
    session['show_overlap'] = not session.get('show_overlap', False)
    # when show overlap clicked conflict will be disable
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    # Redirecting to index will already include the overlap data for the current index

    # Determine if we're showing or hiding overlap
    action = "showOverlap" if session['show_overlap'] else "hide"

    return redirect(url_for('index', action=action))


@app.route('/conflict_action')
def conflict_action():

    # Toggle the show_overlap state in the session
    session['show_conflict'] = not session.get('show_conflict', False)
    session['show_overlap'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    # Redirecting to index will already include the overlap data for the current index
    # Determine if we're showing or hiding overlap
    action = "showConflict" if session['show_conflict'] else "hide"
    return redirect(url_for('index',action=action))

@app.route('/unique1_action')
def unique1_action():

    # Toggle the show_unique1 state in the session
    session['show_unique1'] = not session.get('show_unique1', False)
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique2'] = False
    # Redirecting to index will already include the overlap data for the current index
    action = "showUnique1" if session['show_unique1'] else "hide"
    return redirect(url_for('index',action=action))


@app.route('/unique2_action')
def unique2_action():

    session['show_unique2'] = not session.get('show_unique2', False)
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    action = "showUnique2" if session['show_unique2'] else "hide"

    return redirect(url_for('index',action=action))


if __name__ == '__main__':
    app.run(debug=True)