from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
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
from sqlalchemy import text
import random
from flask_migrate import Migrate
import json





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

migrate = Migrate(app, db)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user and user.assigned_indices:
        try:
            session['assigned_indices'] = json.loads(user.assigned_indices)
        except json.JSONDecodeError:
            session['assigned_indices'] = []
    else:
        session['assigned_indices'] = []
    return user

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
    isAdmin = db.Column(db.Boolean, default=False)  # Admin privilege
    completed_narratives = db.Column(db.Integer, default=0)  # Tracks completed narratives
    assigned_indices = db.Column(db.String, nullable=True)  # Stores assigned indices as a JSON string


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
    id = db.Column(db.Integer, primary_key=True)
    custom_id = db.Column(db.String, nullable=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clause_id = db.Column(db.String, nullable=False)
    clause_type = db.Column(db.String, nullable=False)
    sentence_1 = db.Column(db.Text, nullable=True)  
    sentence_2 = db.Column(db.Text, nullable=True) 
    choice = db.Column(db.String, nullable=False)
    narrative_index = db.Column(db.Integer, nullable=False)

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Delete')
    
# main.py

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))
    
    user_to_delete = User.query.get_or_404(user_id)
    
    # Delete associated responses
    UserResponse.query.filter_by(user_id=user_to_delete.id).delete()
    
    # Delete the user
    db.session.delete(user_to_delete)
    db.session.commit()
    
    flash(f'User {user_to_delete.username} has been deleted.', 'success')
    return redirect(url_for('show_db_contents'))






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
        hashedPassword = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Assign random indices
        total_indices = len(all_narrative_1)
        assigned_indices = random.sample(range(total_indices), 5)
        
        newUser = User(
            username=form.username.data, 
            password=hashedPassword,
            isAdmin=False,  # Set to True if registering an admin
            assigned_indices=json.dumps(assigned_indices)  # Store as JSON string
        )
        db.session.add(newUser)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
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
    if not current_user.isAdmin:
        return "Access denied", 403
    
    users = User.query.all()
    delete_form = DeleteUserForm()
    
    user_data = []
    for user in users:
        responses = UserResponse.query.filter_by(user_id=user.id).all()
        # Load assigned indices
        assigned_indices = json.loads(user.assigned_indices) if user.assigned_indices else []
        total_indices = len(assigned_indices)
        indices_completed = 0

        # Calculate progress per index
        index_progress = {}
        for index in assigned_indices:
            user_responses = [resp for resp in responses if resp.narrative_index == index]
            categories_completed = 0
            total_categories = 4  # overlap, conflict, unique1, unique2
            for category in ['overlap', 'conflict', 'unique1', 'unique2']:
                # Load clauses
                if category == 'overlap':
                    clauses = ast.literal_eval(overlap[index])
                elif category == 'conflict':
                    clauses = ast.literal_eval(conflict[index])
                elif category == 'unique1':
                    clauses = ast.literal_eval(unique1[index])
                elif category == 'unique2':
                    clauses = ast.literal_eval(unique2[index])
                num_clauses = len(clauses)
                num_responses = len([resp for resp in user_responses if resp.clause_type == category])
                if num_clauses > 0 and num_responses >= num_clauses:
                    categories_completed += 1
            progress = int((categories_completed / total_categories) * 100)
            index_progress[index] = progress
            if progress == 100:
                indices_completed += 1

        # Overall progress
        overall_progress = int((indices_completed / total_indices) * 100) if total_indices > 0 else 0

        user_data.append({
            'id': user.id,
            'username': user.username,
            'progress': overall_progress,
            'index_progress': index_progress,
            'responses': responses  # Include responses if you want to display them
        })
    return render_template('admin.html', users=user_data, delete_form=delete_form)



@app.route('/record_response', methods=['POST'])
@login_required
def record_response():
    data = request.get_json()
    clause_id = data['clause_id']
    clause_type = data['clause_type']
    choice = data['choice']
    sentence_1 = data.get('sentence_1', '')  
    sentence_2 = data.get('sentence_2', '')  
    user_id = current_user.id

    narrative_index = session.get('current_index', 0)

    custom_id = f"{user_id}-{narrative_index}-{clause_id}-{clause_type}"

    existing_response = UserResponse.query.filter_by(custom_id=custom_id).first()

    if existing_response:
        existing_response.choice = choice
        existing_response.sentence_1 = sentence_1
        existing_response.sentence_2 = sentence_2
    else:
        response = UserResponse(
            user_id=user_id,
            clause_id=clause_id,
            clause_type=clause_type,
            choice=choice,
            narrative_index=narrative_index,
            custom_id=custom_id,
            sentence_1=sentence_1,
            sentence_2=sentence_2
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

    # Find the existing response without clause_text
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


@app.route('/export_user_responses/<int:user_id>')
@login_required
def export_user_responses(user_id):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    # Query and sort responses by narrative_index and clause_type
    responses = UserResponse.query.filter_by(user_id=user_id)\
                                  .order_by(UserResponse.narrative_index, UserResponse.clause_type)\
                                  .all()

    if not responses:
        flash('No responses found for this user.', 'warning')
        return redirect(url_for('show_db_contents'))

    # Organize responses by narrative_index and clause_type
    data_dict = defaultdict(lambda: defaultdict(list))
    
    for resp in responses:
        narrative_index = resp.narrative_index
        clause = resp.clause_type
        data_dict[narrative_index][clause].append({
            'Paper#': resp.user_id,
            'sentence_1': resp.sentence_1 or "",
            'sentence_2': resp.sentence_2 or "",
            'human_eval': resp.choice
        })

    # Prepare data for DataFrame
    export_data = []
    column_widths = {}
    for narrative_index, clauses in sorted(data_dict.items()):
        # Ensure the narrative_index is within bounds
        if 0 <= narrative_index < len(all_narrative_1):
            review1_text = all_narrative_1[narrative_index]
            review2_text = all_narrative_2[narrative_index]
        else:
            review1_text = "Invalid Index"
            review2_text = "Invalid Index"
        
        row = {
            'Narrative Index': narrative_index,
            'Review1': review1_text,
            'Review2': review2_text
        }
        for clause_type, resp_list in clauses.items():
            row[clause_type.capitalize()] = json.dumps(resp_list)
        
        export_data.append(row)
        
        # Update column widths based on content length
        for key, value in row.items():
            # Initialize with the length of the column name if not already set
            if key not in column_widths:
                column_widths[key] = len(str(key))
            # Update to the maximum length found
            column_widths[key] = max(column_widths[key], len(str(value)))

    # Define all possible clause types for consistent columns
    all_clauses = sorted({resp.clause_type for resp in responses})
    column_order = ['Narrative Index', 'Review1', 'Review2'] + [clause.capitalize() for clause in all_clauses]

    # Create a DataFrame with the specified column order
    df = pd.DataFrame(export_data, columns=column_order)

    # Create a BytesIO buffer to hold the Excel file
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Responses')
        workbook  = writer.book
        worksheet = writer.sheets['Responses']

        # Define a format with text wrapping
        wrap_format = workbook.add_format({'text_wrap': True})

        # Apply dynamic column widths with limits and text wrapping
        for idx, col in enumerate(df.columns):
            # Calculate the width: min(max_length, 100) to prevent overly wide columns
            width = min(max(column_widths[col], 20), 100)  # Adjust min and max as needed
            worksheet.set_column(idx, idx, width, wrap_format)

        # Optionally, freeze the header row for better navigation
        worksheet.freeze_panes(1, 0)

    # Seek to the beginning of the BytesIO buffer
    output.seek(0)

    # Send the file as an attachment
    return send_file(
        output,
        download_name=f"user_{user_id}_responses.xlsx",
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/index')
@login_required
def index():
    if current_user.isAdmin:
        assigned_indices = list(range(len(all_narrative_1)))
        session['assigned_indices'] = assigned_indices
    else:
        assigned_indices = session.get('assigned_indices')
        if assigned_indices is None:
            if current_user.assigned_indices:
                assigned_indices = json.loads(current_user.assigned_indices)
                session['assigned_indices'] = assigned_indices
            else:
                flash('No indices assigned to you. Please contact the administrator.', 'danger')
                return redirect(url_for('logout'))

    current_pos = session.get('current_pos', 0)
    if current_pos >= len(assigned_indices):
        flash('You have completed all assigned narratives.', 'success')
        return redirect(url_for('logout'))

    current_index = assigned_indices[current_pos]
    session['current_index'] = current_index

    # Retrieve toggle states from session
    show_overlap = session.get('show_overlap', False)
    show_conflict = session.get('show_conflict', False)
    show_unique1 = session.get('show_unique1', False)
    show_unique2 = session.get('show_unique2', False)

    narrative1 = all_narrative_1[current_index]
    narrative2 = all_narrative_2[current_index]

    # Parse data
    overlap_raw = ast.literal_eval(overlap[current_index])
    conflict_raw = ast.literal_eval(conflict[current_index])
    unique1_raw = ast.literal_eval(unique1[current_index])
    unique2_raw = ast.literal_eval(unique2[current_index])

    overlap_batch = [
        {
            'sentence_1': clean_text(item['sentence_1']),
            'sentence_2': clean_text(item['sentence_2']),
            'clause_id': f"overlap_{i+1}",
            'clause_type': 'overlap'
        }
        for i, item in enumerate(overlap_raw)
    ]

    conflict_batch = [
        {
            'sentence_1': clean_text(item['sentence_1']),
            'sentence_2': clean_text(item['sentence_2']),
            'clause_id': f"conflict_{i+1}",
            'clause_type': 'conflict'
        }
        for i, item in enumerate(conflict_raw)
    ]

    unique1_batch = [
        {
            'sentence_1': clean_text(item['sentence_1']),
            'sentence_2': None,
            'clause_id': f"unique1_{i+1}",
            'clause_type': 'unique1'
        }
        for i, item in enumerate(unique1_raw)
    ]

    unique2_batch = [
        {
            'sentence_1': None,
            'sentence_2': clean_text(item['sentence_2']),
            'clause_id': f"unique2_{i+1}",
            'clause_type': 'unique2'
        }
        for i, item in enumerate(unique2_raw)
    ]

    # Get saved responses for the current user and index
    responses = UserResponse.query.filter_by(
        user_id=current_user.id,
        narrative_index=current_index
    ).all()

    # Group responses by category
    responses_by_category = defaultdict(list)
    for resp in responses:
        responses_by_category[resp.clause_type].append(resp)

    # Track completion and missing clauses
    categories = {
        'overlap': overlap_batch,
        'conflict': conflict_batch,
        'unique1': unique1_batch,
        'unique2': unique2_batch
    }

    category_missing = {}
    categories_completed = 0
    total_categories = 4
    for cat_name, clauses_list in categories.items():
        total_clauses = len(clauses_list)
        answered_clauses = len(responses_by_category.get(cat_name, []))
        missing_clauses_count = total_clauses - answered_clauses

        if missing_clauses_count == 0 and total_clauses > 0:
            categories_completed += 1
            category_missing[cat_name] = []
        else:
            # Identify which clauses are missing
            answered_ids = {r.clause_id for r in responses_by_category.get(cat_name, [])}
            missing_clauses = [c for c in clauses_list if c['clause_id'] not in answered_ids]
            category_missing[cat_name] = missing_clauses

    # Calculate overall progress
    progress = int((categories_completed / total_categories) * 100)

    return render_template(
        'index.html',
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
        saved_responses={resp.clause_id: resp.choice for resp in responses},
        progress=progress,
        category_missing=category_missing # Pass info about missing clauses
    )

@app.route('/next')
@login_required
def next_narrative():
    # Retrieve assigned indices
    if current_user.isAdmin:
        # Admins access all indices
        assigned_indices = list(range(len(all_narrative_1)))
    else:
        # Non-admins use assigned indices
        assigned_indices = session.get('assigned_indices')
        if assigned_indices is None:
            if current_user.assigned_indices:
                assigned_indices = json.loads(current_user.assigned_indices)
                session['assigned_indices'] = assigned_indices
            else:
                flash('No indices assigned to you. Please contact the administrator.', 'danger')
                return redirect(url_for('logout'))

    current_pos = session.get('current_pos', 0)
    current_index = assigned_indices[current_pos]

    if not current_user.isAdmin:
        # Non-admin users need to complete all required responses
        required_categories = ['overlap', 'conflict', 'unique1', 'unique2']

        user_responses = UserResponse.query.filter_by(
            user_id=current_user.id,
            narrative_index=current_index
        ).all()

        responses_by_category = defaultdict(list)
        for resp in user_responses:
            responses_by_category[resp.clause_type].append(resp)

        # Check if all clauses in each category have responses
        all_completed = True
        for category in required_categories:
            if category == 'overlap':
                clauses = ast.literal_eval(overlap[current_index])
            elif category == 'conflict':
                clauses = ast.literal_eval(conflict[current_index])
            elif category == 'unique1':
                clauses = ast.literal_eval(unique1[current_index])
            elif category == 'unique2':
                clauses = ast.literal_eval(unique2[current_index])
            num_clauses = len(clauses)
            if len(responses_by_category.get(category, [])) < num_clauses:
                all_completed = False
                break

        if not all_completed:
            flash('Please complete all required responses before proceeding.', 'warning')
            return redirect(url_for('index'))

    # Proceed to next index
    current_pos += 1
    if current_pos >= len(assigned_indices):
        flash('You have completed all assigned narratives.', 'success')
        return redirect(url_for('logout'))
    else:
        session['current_pos'] = current_pos
        session['current_index'] = assigned_indices[current_pos]
        # Reset clause toggles when moving to the next narrative
        session['show_overlap'] = False
        session['show_conflict'] = False
        session['show_unique1'] = False
        session['show_unique2'] = False
        return redirect(url_for('index'))

@app.route('/prev')
@login_required
def prev_narrative():
    # Reset clause toggles
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False

    # Retrieve assigned indices
    if current_user.isAdmin:
        # Admins access all indices
        assigned_indices = list(range(len(all_narrative_1)))
    else:
        # Non-admins use assigned indices
        assigned_indices = session.get('assigned_indices')
        if assigned_indices is None:
            if current_user.assigned_indices:
                assigned_indices = json.loads(current_user.assigned_indices)
                session['assigned_indices'] = assigned_indices
            else:
                flash('No indices assigned to you. Please contact the administrator.', 'danger')
                return redirect(url_for('logout'))

    current_pos = session.get('current_pos', 0)
    if current_pos > 0:
        current_pos -= 1
        session['current_pos'] = current_pos
        session['current_index'] = assigned_indices[current_pos]
    else:
        flash('You are at the first narrative.', 'info')

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