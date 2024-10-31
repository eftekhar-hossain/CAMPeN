from flask import Flask, render_template, request, redirect, url_for, session
import pandas as pd
import ast,re
from get_highlighted import get_overlap_narratives, get_conflict_narratives, get_unique_narratives

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key for sessions
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



@app.route('/')
def index():
    global current_index
    # Retrieve the `show_overlap` toggle state from the session
    show_overlap = session.get('show_overlap', False)
    # Retrieve the `show_conflict` toggle state from the session
    show_conflict = session.get('show_conflict', False)
    # Retrieve the `show_unique1` toggle state from the session
    show_unique1 = session.get('show_unique1', False)
    # Retrieve the `show_unique2` toggle state from the session
    show_unique2 = session.get('show_unique2', False)

    narrative1 = all_narrative_1[current_index]
    narrative2 = all_narrative_2[current_index]
    overlap_batch = ast.literal_eval(overlap[current_index])
    overlap_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                     'sentence_2': clean_text( item['sentence_2'])} 
                          for item in ast.literal_eval(overlap[current_index])]
    
    conflict_batch = ast.literal_eval(conflict[current_index])
    conflict_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                     'sentence_2': clean_text( item['sentence_2'])} 
                          for item in ast.literal_eval(conflict[current_index])]
    unique1_batch = ast.literal_eval(unique1[current_index])
    unique1_batch = [{'sentence_1': clean_text(item['sentence_1']), 
                     'sentence_2': item['sentence_2']} 
                          for item in ast.literal_eval(unique1[current_index])]
    unique2_batch = ast.literal_eval(unique2[current_index])
    unique2_batch = [{'sentence_1': item['sentence_1'], 
                     'sentence_2': clean_text(item['sentence_2'])} 
                          for item in ast.literal_eval(unique2[current_index])]
    # print(overlap_batch)

    # # a list of two narratives where overlap sentences are highlighted
    # overlap_highlighted = get_overlap_narratives(narrative1,narrative2, overlap_batch, show_overlap)
    # # print(overlap_highlighted)

    # # a list of two narratives where overlap sentences are highlighted
    # conflict_highlighted = get_conflict_narratives(narrative1, narrative2, conflict_batch, show_conflict)
    # # print(conflict_highlighted)

    # # a list of two narratives where unique sentences are highlighted
    # unique_highlighted = get_unique_narratives(narrative1, narrative2, unique1_batch, 
    #                                              unique2_batch, show_unique1, show_unique2)
    # print(conflict_highlighted)



    return render_template('index.html', file=elem, current_index=current_index, 
                           overlap= overlap_batch if show_overlap else [],
                           conflict= conflict_batch if show_conflict else [],
                           show_overlap=show_overlap, show_conflict=show_conflict,
                           unique1= unique1_batch if show_unique1 else [],
                           unique2= unique2_batch if show_unique2 else [],
                           show_unique1=show_unique1, show_unique2=show_unique2)


@app.route('/next')
def next_narrative():

    # if we want that after pressing the next button clause button reset
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    global current_index
    # Increment index but keep it within the bounds
    if current_index < len(elem['n1']) - 1:
        current_index += 1
    return redirect(url_for('index'))

@app.route('/prev')
def prev_narrative():
    # if we want that after pressing the prev button clause button reset
    session['show_overlap'] = False
    session['show_conflict'] = False
    session['show_unique1'] = False
    session['show_unique2'] = False
    global current_index
    # Decrement index but keep it within the bounds
    if current_index > 0:
        current_index -= 1
    return redirect(url_for('index'))

@app.route('/overlap_action')
def overlap_action():

    # Toggle the `show_overlap` state in the session
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

    # Toggle the `show_overlap` state in the session
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

    # Toggle the `show_unique1` state in the session
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
