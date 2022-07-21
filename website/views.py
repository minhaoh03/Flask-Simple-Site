from flask import Blueprint, jsonify, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note, db
import json


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')
        
        if len(note) < 1:
            flash('Note is too short!', category='ERROR')
        else:
            newNote = Note(data=note, user_id=current_user.id)
            db.session.add(newNote)
            db.session.commit()
            flash('Note added!', category="SUCCESS")    
            
    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods=['POST'])
def deleteNote():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
    return jsonify({})