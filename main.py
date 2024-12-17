from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
import pandas as pd
import ast, re
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
import os

user_narratives = {}  # Global dictionary to store per-user narratives
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key for sessions

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'testingKey' # Replace with a secure key for production
db.init_app(app)
bcrypt.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

migrate = Migrate(app, db)

def clean_text(text):
    return re.sub(r'\s+', ' ', re.sub(r"[\"“”:']", "", str(text))).strip()

# Load initial data from annotation_oct18.xlsx (no Paper# column expected)
data = pd.read_excel("annotation_oct18.xlsx")

all_narrative_1 = data['Review1'].apply(clean_text).tolist()
all_narrative_2 = data['Review2'].apply(clean_text).tolist()
overlap = data['is_overlap'].tolist()
conflict = data['is_conflict'].tolist()
unique1 = data['is_unique_n1'].tolist()
unique2 = data['is_unique_n2'].tolist()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    isAdmin = db.Column(db.Boolean, default=False)
    completed_narratives = db.Column(db.Integer, default=0)
    assigned_indices = db.Column(db.String, nullable=True)

class registerForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existingUserUsername = User.query.filter_by(username=username.data).first()
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

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user and user.assigned_indices:
        try:
            assigned_indices = json.loads(user.assigned_indices)
            session['assigned_indices'] = assigned_indices
        except json.JSONDecodeError:
            session['assigned_indices'] = []
    else:
        session['assigned_indices'] = []
    return user

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    user_to_delete = User.query.get_or_404(user_id)
    UserResponse.query.filter_by(user_id=user_to_delete.id).delete()
    db.session.delete(user_to_delete)
    db.session.commit()

    flash(f'User {user_to_delete.username} has been deleted.', 'success')
    return redirect(url_for('show_db_contents'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['current_pos'] = 0
            assigned_indices = json.loads(user.assigned_indices) if user.assigned_indices else []

            if user.isAdmin:
                # Admins skip assignment logic and go directly to admin page
                return redirect(url_for('show_db_contents'))
            else:
                if assigned_indices:
                    session['current_index'] = assigned_indices[0]

                    # Fallback if no custom narratives loaded for this user
                    if user.id not in user_narratives:
                        user_narratives[user.id] = {
                            'all_narrative_1': all_narrative_1,
                            'all_narrative_2': all_narrative_2,
                            'overlap': overlap,
                            'conflict': conflict,
                            'unique1': unique1,
                            'unique2': unique2
                        }

                # Redirect to index regardless of assignments; index will handle rendering
                return redirect(url_for('index'))

    # After form validation fails
    flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registerForm()
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        newUser = User(
            username=form.username.data,
            password=hashedPassword,
            isAdmin=False,
            assigned_indices=json.dumps([])
        )
        db.session.add(newUser)
        db.session.commit()
        flash('Registration successful. Please log in.', 'registerSuccess')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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
        assigned_indices = json.loads(user.assigned_indices) if user.assigned_indices else []
        total_indices = len(assigned_indices)
        indices_completed = 0

        if user.id in user_narratives and user_narratives[user.id]['all_narrative_1']:
            user_overlap = user_narratives[user.id]['overlap']
            user_conflict = user_narratives[user.id]['conflict']
            user_unique1 = user_narratives[user.id]['unique1']
            user_unique2 = user_narratives[user.id]['unique2']
        else:
            user_overlap = overlap
            user_conflict = conflict
            user_unique1 = unique1
            user_unique2 = unique2

        # After computing index_progress as before, also compute how many narratives are fully completed.
        index_progress = {}
        for index in assigned_indices:
            user_responses = [resp for resp in responses if resp.narrative_index == index]
            categories_completed = 0
            total_categories = 4  # overlap, conflict, unique1, unique2

            for category in ['overlap', 'conflict', 'unique1', 'unique2']:
                if category == 'overlap':
                    clauses = ast.literal_eval(user_overlap[index])
                elif category == 'conflict':
                    clauses = ast.literal_eval(user_conflict[index])
                elif category == 'unique1':
                    clauses = ast.literal_eval(user_unique1[index])
                elif category == 'unique2':
                    clauses = ast.literal_eval(user_unique2[index])

                num_clauses = len(clauses)
                num_responses = len([resp for resp in user_responses if resp.clause_type == category])
                if num_clauses > 0 and num_responses >= num_clauses:
                    categories_completed += 1

            progress = int((categories_completed / total_categories) * 100)
            index_progress[index] = progress

        # Count how many narratives are fully completed
        indices_completed = sum(1 for p in index_progress.values() if p == 100)

        overall_progress = int((indices_completed / total_indices) * 100) if total_indices > 0 else 0

        # Add these values to the user_data dictionary
        user_data.append({
            'id': user.id,
            'username': user.username,
            'progress': overall_progress,
            'index_progress': index_progress,  # still included if needed
            'responses': responses,
            'indices_completed': indices_completed,
            'total_indices': total_indices
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

@app.route('/add_excel', methods=['POST'])
@login_required
def add_excel():
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    if 'new_excel' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('show_db_contents'))

    file = request.files['new_excel']
    if file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('show_db_contents'))

    if not file.filename.lower().endswith(('.xlsx', '.xls')):
        flash('Invalid file type. Please upload an Excel file.', 'danger')
        return redirect(url_for('show_db_contents'))

    try:
        new_data = pd.read_excel(file)
    except Exception as e:
        flash(f'Failed to read Excel file: {str(e)}', 'danger')
        return redirect(url_for('show_db_contents'))

    required_columns = {'Review1', 'Review2', 'is_overlap', 'is_conflict', 'is_unique_n1', 'is_unique_n2'}
    if not required_columns.issubset(new_data.columns):
        flash('Uploaded file does not have the required columns.', 'danger')
        return redirect(url_for('show_db_contents'))

    if new_data.empty:
        flash('The uploaded Excel file is empty.', 'warning')
        return redirect(url_for('show_db_contents'))

    global all_narrative_1, all_narrative_2, overlap, conflict, unique1, unique2
    all_narrative_1.clear()
    all_narrative_2.clear()
    overlap.clear()
    conflict.clear()
    unique1.clear()
    unique2.clear()

    all_narrative_1.extend(new_data['Review1'].apply(clean_text).tolist())
    all_narrative_2.extend(new_data['Review2'].apply(clean_text).tolist())
    overlap.extend(new_data['is_overlap'].tolist())
    conflict.extend(new_data['is_conflict'].tolist())
    unique1.extend(new_data['is_unique_n1'].tolist())
    unique2.extend(new_data['is_unique_n2'].tolist())

    # Delete all old responses
    UserResponse.query.delete()

    # Reset all users' assigned narratives
    users = User.query.all()
    for user in users:
        user.assigned_indices = json.dumps([])

    db.session.commit()

    # Clear user_narratives since all changed
    user_narratives.clear()

    flash(f'Successfully replaced narratives with {len(all_narrative_1)} new narratives from uploaded Excel.', 'success')
    flash('No narratives are currently assigned to any user. Please assign narratives to users as needed.', 'info')
    return redirect(url_for('show_db_contents'))

@app.route('/assign_excel_to_user/<int:user_id>', methods=['POST'])
@login_required
def assign_excel_to_user(user_id):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    user = User.query.get_or_404(user_id)

    if 'new_excel' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('show_db_contents'))

    file = request.files['new_excel']
    if file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('show_db_contents'))

    if not file.filename.lower().endswith(('.xlsx', '.xls')):
        flash('Invalid file type. Please upload an Excel file.', 'danger')
        return redirect(url_for('show_db_contents'))

    try:
        new_data = pd.read_excel(file)
    except Exception as e:
        flash(f'Failed to read Excel file: {str(e)}', 'danger')
        return redirect(url_for('show_db_contents'))

    required_columns = {'Review1', 'Review2', 'is_overlap', 'is_conflict', 'is_unique_n1', 'is_unique_n2'}
    if not required_columns.issubset(new_data.columns):
        flash('Uploaded file does not have the required columns.', 'danger')
        return redirect(url_for('show_db_contents'))

    if new_data.empty:
        flash('The uploaded Excel file is empty.', 'warning')
        return redirect(url_for('show_db_contents'))

    user_all_narrative_1 = new_data['Review1'].apply(clean_text).tolist()
    user_all_narrative_2 = new_data['Review2'].apply(clean_text).tolist()
    user_overlap = new_data['is_overlap'].tolist()
    user_conflict = new_data['is_conflict'].tolist()
    user_unique1 = new_data['is_unique_n1'].tolist()
    user_unique2 = new_data['is_unique_n2'].tolist()

    # Clear user responses for old narratives
    UserResponse.query.filter_by(user_id=user_id).delete()

    assigned_indices = list(range(len(user_all_narrative_1)))
    user.assigned_indices = json.dumps(assigned_indices)

    db.session.commit()

    user_narratives[user_id] = {
        'all_narrative_1': user_all_narrative_1,
        'all_narrative_2': user_all_narrative_2,
        'overlap': user_overlap,
        'conflict': user_conflict,
        'unique1': user_unique1,
        'unique2': user_unique2
    }

    flash(f'Successfully assigned {len(assigned_indices)} new narratives to user {user.username}.', 'success')
    return redirect(url_for('show_db_contents'))

def get_paper_number(narrative_index, user_id):
    # Fetch data from user or global narratives
    if user_id in user_narratives and user_narratives[user_id]['all_narrative_1']:
        overlap_str = user_narratives[user_id]['overlap'][narrative_index]
        conflict_str = user_narratives[user_id]['conflict'][narrative_index]
        unique1_str = user_narratives[user_id]['unique1'][narrative_index]
        unique2_str = user_narratives[user_id]['unique2'][narrative_index]
    else:
        overlap_str = overlap[narrative_index]
        conflict_str = conflict[narrative_index]
        unique1_str = unique1[narrative_index]
        unique2_str = unique2[narrative_index]

    # Each is a string representation of a list of dicts
    for cat_str in [overlap_str, conflict_str, unique1_str, unique2_str]:
        cat_data = ast.literal_eval(cat_str)
        if cat_data and 'Paper#' in cat_data[0]:
            return cat_data[0]['Paper#']

    return "Unknown"

@app.route('/export_user_responses/<int:user_id>')
@login_required
def export_user_responses(user_id):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('show_db_contents'))

    responses = UserResponse.query.filter_by(user_id=user_id)\
                                  .order_by(UserResponse.narrative_index, UserResponse.clause_type)\
                                  .all()

    if not responses:
        flash('No responses found for this user.', 'warning')
        return redirect(url_for('show_db_contents'))

    data_dict = defaultdict(lambda: defaultdict(list))
    for resp in responses:
        narrative_index = resp.narrative_index
        paper_num = get_paper_number(narrative_index, user_id)

        data_dict[narrative_index][resp.clause_type].append({
            'Paper#': paper_num,
            'sentence_1': resp.sentence_1 or "",
            'sentence_2': resp.sentence_2 or "",
            'human_eval': resp.choice
        })

    export_data = []
    column_widths = {}
    if user_id in user_narratives and user_narratives[user_id]['all_narrative_1']:
        narrative_1_source = user_narratives[user_id]['all_narrative_1']
        narrative_2_source = user_narratives[user_id]['all_narrative_2']
    else:
        narrative_1_source = all_narrative_1
        narrative_2_source = all_narrative_2

    for narrative_index, clauses in sorted(data_dict.items()):
        if 0 <= narrative_index < len(narrative_1_source):
            review1_text = narrative_1_source[narrative_index]
            review2_text = narrative_2_source[narrative_index]
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

        for key, value in row.items():
            if key not in column_widths:
                column_widths[key] = len(str(key))
            column_widths[key] = max(column_widths[key], len(str(value)))

    all_clauses = sorted({resp.clause_type for resp in responses})
    column_order = ['Narrative Index', 'Review1', 'Review2'] + [clause.capitalize() for clause in all_clauses]
    df = pd.DataFrame(export_data, columns=column_order)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Responses')
        workbook = writer.book
        worksheet = writer.sheets['Responses']
        wrap_format = workbook.add_format({'text_wrap': True})
        for idx, col in enumerate(df.columns):
            width = min(max(column_widths[col], 20), 100)
            worksheet.set_column(idx, idx, width, wrap_format)
        worksheet.freeze_panes(1, 0)

    output.seek(0)
    return send_file(
        output,
        download_name=f"user_{user_id}_responses.xlsx",
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/delete_narrative/<int:narrative_index>', methods=['POST'])
@login_required
def delete_narrative(narrative_index):
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_narratives'))

    if narrative_index < 0 or narrative_index >= len(all_narrative_1):
        flash('Invalid narrative index.', 'danger')
        return redirect(url_for('show_narratives'))

    del all_narrative_1[narrative_index]
    del all_narrative_2[narrative_index]
    del overlap[narrative_index]
    del conflict[narrative_index]
    del unique1[narrative_index]
    del unique2[narrative_index]

    flash('Narrative deleted successfully.', 'success')
    return redirect(url_for('show_narratives'))

@app.route('/edit_response', methods=['POST'])
@login_required
def edit_response():
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    response_id = request.form.get('response_id')
    new_choice = request.form.get('new_choice')

    response = UserResponse.query.get(response_id)
    if not response:
        flash('Response not found.', 'danger')
        return redirect(url_for('show_db_contents'))

    response.choice = new_choice
    db.session.commit()

    flash('Response updated successfully.', 'success')
    return redirect(url_for('show_db_contents'))

@app.route('/delete_specific_response', methods=['POST'])
@login_required
def delete_specific_response():
    if not current_user.isAdmin:
        flash('Access denied.', 'danger')
        return redirect(url_for('show_db_contents'))

    response_id = request.form.get('response_id')
    response = UserResponse.query.get(response_id)
    if not response:
        flash('Response not found.', 'danger')
        return redirect(url_for('show_db_contents'))

    db.session.delete(response)
    db.session.commit()

    flash('Response deleted successfully.', 'success')
    return redirect(url_for('show_db_contents'))

@app.route('/upload_pdf', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    if not current_user.isAdmin:
        flash('Access denied', 'danger')
        return redirect(url_for('show_db_contents'))
    
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('No PDF file selected', 'danger')
            return redirect(url_for('upload_pdf'))
        
        pdf_file = request.files['pdf_file']
        if pdf_file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('upload_pdf'))
        
        if not pdf_file.filename.lower().endswith('.pdf'):
            flash('Invalid file type. Please upload a PDF file', 'danger')
            return redirect(url_for('upload_pdf'))
        
        pdf_path = 'static/guidelines.pdf'
        pdf_file.save(pdf_path)

        flash('PDF uploaded successfully. Users can now view the latest guidelines.', 'success')
        return redirect(url_for('show_db_contents'))
    
    return redirect(url_for('show_db_contents'))


@app.route('/view_guidelines')
@login_required
def view_guidelines():
    pdf_path = 'static/guidelines.pdf'
    if not os.path.exists(pdf_path):
        flash('No guidelines PDF available. Please contact the administrator.', 'guidelines_warning')
        return redirect(url_for('index'))
    
    return send_file(pdf_path, as_attachment=True, download_name='Guidelines.pdf')

@app.route('/index')
@login_required
def index():
    if current_user.isAdmin:
        return redirect(url_for('show_db_contents'))

    if 'assigned_indices' not in session:
        if current_user.assigned_indices:
            session['assigned_indices'] = json.loads(current_user.assigned_indices)
        else:
            session['assigned_indices'] = []

    assigned_indices = session['assigned_indices']
    if not assigned_indices:
        user_responses = UserResponse.query.filter_by(user_id=current_user.id).all()
        if user_responses:
            return render_template('completed.html')
        else:
            return render_template('noAssignments.html')

    if current_user.id not in user_narratives:
        user_narratives[current_user.id] = {
            'all_narrative_1': all_narrative_1,
            'all_narrative_2': all_narrative_2,
            'overlap': overlap,
            'conflict': conflict,
            'unique1': unique1,
            'unique2': unique2
        }

    narratives = user_narratives[current_user.id]
    all_narrative_1_local = narratives['all_narrative_1']
    all_narrative_2_local = narratives['all_narrative_2']
    overlap_local = narratives['overlap']
    conflict_local = narratives['conflict']
    unique1_local = narratives['unique1']
    unique2_local = narratives['unique2']

    current_pos = session.get('current_pos', 0)
    if current_pos >= len(assigned_indices):
        flash('You have completed all assigned narratives.', 'success')
        return render_template('completed.html')

    current_index = assigned_indices[current_pos]
    session['current_index'] = current_index

    show_overlap = session.get('show_overlap', False)
    show_conflict = session.get('show_conflict', False)
    show_unique1 = session.get('show_unique1', False)
    show_unique2 = session.get('show_unique2', False)

    narrative1 = all_narrative_1_local[current_index]
    narrative2 = all_narrative_2_local[current_index]

    overlap_raw = ast.literal_eval(overlap_local[current_index])
    conflict_raw = ast.literal_eval(conflict_local[current_index])
    unique1_raw = ast.literal_eval(unique1_local[current_index])
    unique2_raw = ast.literal_eval(unique2_local[current_index])

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

    responses = UserResponse.query.filter_by(
        user_id=current_user.id,
        narrative_index=current_index
    ).all()

    responses_by_category = defaultdict(list)
    for resp in responses:
        responses_by_category[resp.clause_type].append(resp)

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
            answered_ids = {r.clause_id for r in responses_by_category.get(cat_name, [])}
            missing_clauses = [c for c in clauses_list if c['clause_id'] not in answered_ids]
            category_missing[cat_name] = missing_clauses

    progress = int((categories_completed / total_categories) * 100)
    elem = {"n1": all_narrative_1_local, "n2": all_narrative_2_local}
    total_indices = len(assigned_indices)

    return render_template(
        'index.html',
        file=elem,
        current_index=current_index,
        total_indices=total_indices,
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
        category_missing=category_missing
    )

@app.route('/next')
@login_required
def next_narrative():
    if current_user.isAdmin:
        assigned_indices = list(range(len(all_narrative_1)))
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
    current_index = assigned_indices[current_pos]

    if current_user.id in user_narratives and len(user_narratives[current_user.id]['all_narrative_1']) > 0:
        overlap_local = user_narratives[current_user.id]['overlap']
        conflict_local = user_narratives[current_user.id]['conflict']
        unique1_local = user_narratives[current_user.id]['unique1']
        unique2_local = user_narratives[current_user.id]['unique2']
    else:
        overlap_local = overlap
        conflict_local = conflict
        unique1_local = unique1
        unique2_local = unique2

    if not current_user.isAdmin:
        required_categories = ['overlap', 'conflict', 'unique1', 'unique2']
        user_responses = UserResponse.query.filter_by(
            user_id=current_user.id,
            narrative_index=current_index
        ).all()
        responses_by_category = defaultdict(list)
        for resp in user_responses:
            responses_by_category[resp.clause_type].append(resp)

        all_completed = True
        for category in required_categories:
            if category == 'overlap':
                clauses = ast.literal_eval(overlap_local[current_index])
            elif category == 'conflict':
                clauses = ast.literal_eval(conflict_local[current_index])
            elif category == 'unique1':
                clauses = ast.literal_eval(unique1_local[current_index])
            elif category == 'unique2':
                clauses = ast.literal_eval(unique2_local[current_index])

            num_clauses = len(clauses)
            answered_clauses = len(responses_by_category.get(category, []))
            if answered_clauses < num_clauses:
                all_completed = False
                break

        if not all_completed:
            flash('Please complete all required responses before proceeding.', 'index')
            return redirect(url_for('index'))

    current_pos += 1
    if current_pos >= len(assigned_indices):
        flash('You have completed all assigned narratives.', 'index')
        return render_template('completed.html')
    else:
        session['current_pos'] = current_pos
        session['current_index'] = assigned_indices[current_pos]
        # Reset clause toggles
        session['show_overlap'] = False
        session['show_conflict'] = False
        session['show_unique1'] = False
        session['show_unique2'] = False
        return redirect(url_for('index'))

@app.route('/prev')
@login_required
def prev_narrative():
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False

    if current_user.isAdmin:
        assigned_indices = list(range(len(all_narrative_1)))
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
    if current_pos > 0:
        current_pos -= 1
        session['current_pos'] = current_pos
        session['current_index'] = assigned_indices[current_pos]
    else:
        flash('You are at the first narrative.', 'index')

    return redirect(url_for('index'))

@app.route('/overlap_action')
def overlap_action():
    session['show_overlap'] = not session.get('show_overlap', False)
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    action = "showOverlap" if session['show_overlap'] else "hide"
    return redirect(url_for('index', action=action))

@app.route('/conflict_action')
def conflict_action():
    session['show_conflict'] = not session.get('show_conflict', False)
    session['show_overlap'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    action = "showConflict" if session['show_conflict'] else "hide"
    return redirect(url_for('index',action=action))

@app.route('/unique1_action')
def unique1_action():
    session['show_unique1'] = not session.get('show_unique1', False)
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique2'] = False
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
