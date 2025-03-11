import platform
from flask import Flask, request, session, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import datetime as dt
import os
from dotenv import load_dotenv
import requests
import json
import subprocess

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

app.secret_key = os.getenv('SERVER_SECRET_KEY')

# Load database URI directly from the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
# Disable modification tracking overhead
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# Define the User model


class User(db.Model):
    __tablename__ = 'users'
    user_sk = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Define the UserToken model


class UserToken(db.Model):
    __tablename__ = 'user_token'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_sk = db.Column(db.Integer, db.ForeignKey(
        'users.user_sk'))
    platform = db.Column(db.String(100), db.Enum('X', 'FB', name='type_enum'), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    access_token_secret = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255))
    

# Define the SparkLedger model


class SparkLedger(db.Model):
    __tablename__ = 'spark_ledger'
    id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, db.ForeignKey('users.user_sk'))
    credit_score = db.Column(db.Integer)
    debit_score = db.Column(db.Integer)
    time = db.Column(db.DateTime, default=datetime.utcnow)

# Define the Activity model

class Activity(db.Model):
    __tablename__ = 'activity'
    activity_id = db.Column(db.Integer, primary_key=True)
    athlete_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'), nullable=False)
    name = db.Column(db.String(255))
    distance = db.Column(db.Float, default=0.0)
    moving_time = db.Column(db.Integer, default=0)
    elapsed_time = db.Column(db.Integer, default=0)
    total_elevation_gain = db.Column(db.Float, default=0.0)
    type = db.Column(db.String(50), db.Enum('run', 'walk', 'hike', 'swim', 'ride', name='type_enum'))
    start_date = db.Column(db.DateTime, default=dt.date.today())
    description = db.Column(db.Text)
    calories = db.Column(db.Float, default=0.0)

# Define the User Preferences model


class UserPreferences(db.Model):
    __tablename__ = 'user_preferences'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    supplements_id = db.Column(db.Integer, db.ForeignKey('supplements.id'))
    shoe_type_id = db.Column(db.Integer, db.ForeignKey('shoe_type.id'))
    injuries_id = db.Column(db.Integer, db.ForeignKey('injuries.id'))
    running_surface = db.Column(db.String(100), nullable=False)

    supplements = db.relationship('Supplements', backref='user_preferences')
    shoe_type = db.relationship('ShoeType', backref='user_preferences')
    injuries = db.relationship('Injuries', backref='user_preferences')
    
class Supplements(db.Model):
    __tablename__ = 'supplements'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

class ShoeType(db.Model):
    __tablename__ = 'shoe_type'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

class Injuries(db.Model):
    __tablename__ = 'injuries'
    id = db.Column(db.Integer, primary_key=True)
    tennis_elbow = db.Column(db.Boolean, default=False)
    muscle_strain = db.Column(db.Boolean, default=False)
    bicep_tendonitis = db.Column(db.Boolean, default=False)
    fracture = db.Column(db.Boolean, default=False)
    forearm_strain = db.Column(db.Boolean, default=False)
    
# Routes to interact with users


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created", "user_sk": new_user.user_sk}), 201


@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{"user_sk": user.user_sk, "username": user.username, "email": user.email} for user in users])


@app.before_request
def create_tables():
    db.create_all()
    
# Routes to set or update user preferences


@app.route("/user/preferences/<user_id>",methods=["POST"])
def set_user_preferences(user_id):
    
    # Set preferences for a specific user.
    
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    
    required_fields = [ "shoe_type", "injuries", "running_surface"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
        
    # Create records
    
    supplements_data = data["supplements"]
    shoe_type_data = data["shoe_type"]
    injuries_data = data["injuries"]

    if supplements_data:
        supplements = Supplements(
            name=supplements_data["name"],
            model=supplements_data["model"],
            description=supplements_data["description"]
        )
        db.session.add(supplements)
        db.commit()
    else:
        supplements = None
        
    shoe_type = ShoeType(
        name=shoe_type_data["name"],
        model=shoe_type_data["model"],
        description=shoe_type_data["description"]
    )
    injuries = Injuries(
        tennis_elbow=injuries_data["tennis_elbow"],
        muscle_strain=injuries_data["muscle_strain"],
        bicep_tendonitis=injuries_data["bicep_tendonitis"],
        fracture=injuries_data["fracture"],
        forearm_strain=injuries_data["forearm_strain"]
    )

    db.session.add(shoe_type)
    db.session.add(injuries)
    db.session.commit()

    user_preferences = UserPreferences(
        user_id=user_id,
        supplements_id=supplements.id if supplements else None,
        shoe_type_id=shoe_type.id,
        injuries_id=injuries.id,
        running_surface=data["running_surface"]
    )

    db.session.add(user_preferences)
    db.session.commit()

    
    return jsonify({"message": "Preferences saved successfully."}), 200


@app.route("/user/preferences/<user_id>",methods=["GET"])
def get_user_preferences(user_id):
    
    # Retrieve preferences for a specific user.
    
    user_pref = UserPreferences.query.filter_by(user_id=user_id).first()
    if not user_pref:
        return jsonify({"error": "No preferences found for the specified user."}), 404
    
    response = {
        "user_id": user_pref.user_id,
        "supplements": {
            "name": user_pref.supplements.name,
            "model": user_pref.supplements.model,
            "description": user_pref.supplements.description
        } if user_pref.supplements else None,
        "shoe_type": {
            "name": user_pref.shoe_type.name,
            "model": user_pref.shoe_type.model,
            "description": user_pref.shoe_type.description
        },
        "injuries": {
            "tennis_elbow": user_pref.injuries.tennis_elbow,
            "muscle_strain": user_pref.injuries.muscle_strain,
            "bicep_tendonitis": user_pref.injuries.bicep_tendonitis,
            "fracture": user_pref.injuries.fracture,
            "forearm_strain": user_pref.injuries.forearm_strain
        },
        "running_surface": user_pref.running_surface
    }
    
    return jsonify({"preferences": response}), 200


@app.route("/user/preferences",methods=["GET"])
def get_all_user_preferences():
    
    # Retrieve preferences for all users.
    
    response = []
    user_preferences = UserPreferences.query.all()
    if not user_preferences:
        return jsonify({"error": "No user preferences found."}), 404
    
    for user_pref in user_preferences:
        response.append({
            "user_id": user_pref.user_id,
            "supplements": {
                "name": user_pref.supplements.name,
                "model": user_pref.supplements.model,
                "description": user_pref.supplements.description
            } if user_pref.supplements else None,
            "shoe_type": {
                "name": user_pref.shoe_type.name,
                "model": user_pref.shoe_type.model,
                "description": user_pref.shoe_type.description
            },
            "injuries": {
                "tennis_elbow": user_pref.injuries.tennis_elbow,
                "muscle_strain": user_pref.injuries.muscle_strain,
                "bicep_tendonitis": user_pref.injuries.bicep_tendonitis,
                "fracture": user_pref.injuries.fracture,
                "forearm_strain": user_pref.injuries.forearm_strain
            },
            "running_surface": user_pref.running_surface
        })

    
    return jsonify({"preferences": response}), 200



@app.route("/user/preferences/<user_id>", methods=["PUT"])
def modify_user_preferences(user_id):
    
    # Modify preferences for a specific user.
    
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    user_pref = UserPreferences.query.filter_by(user_id=user_id).first()
    if not user_pref:
        return jsonify({"error": "User preferences not found."}), 404

    # Update existing related records
    if "supplements" in data:
        supp_data = data["supplements"]
        user_pref.supplements.name = supp_data.get("name", user_pref.supplements.name)
        user_pref.supplements.model = supp_data.get("model", user_pref.supplements.model)
        user_pref.supplements.description = supp_data.get("description", user_pref.supplements.description)

    if "shoe_type" in data:
        shoe_data = data["shoe_type"]
        user_pref.shoe_type.name = shoe_data.get("name", user_pref.shoe_type.name)
        user_pref.shoe_type.model = shoe_data.get("model", user_pref.shoe_type.model)
        user_pref.shoe_type.description = shoe_data.get("description", user_pref.shoe_type.description)

    if "injuries" in data:
        injuries_data = data["injuries"]
        user_pref.injuries.tennis_elbow = injuries_data.get("tennis_elbow", user_pref.injuries.tennis_elbow)
        user_pref.injuries.muscle_strain = injuries_data.get("muscle_strain", user_pref.injuries.muscle_strain)
        user_pref.injuries.bicep_tendonitis = injuries_data.get("bicep_tendonitis", user_pref.injuries.bicep_tendonitis)
        user_pref.injuries.fracture = injuries_data.get("fracture", user_pref.injuries.fracture)
        user_pref.injuries.forearm_strain = injuries_data.get("forearm_strain", user_pref.injuries.forearm_strain)

    if "running_surface" in data:
        user_pref.running_surface = data["running_surface"]

    db.session.commit()

    return jsonify({"message": "Preferences modified successfully."}), 200


@app.route("/user/preferences/<user_id>", methods=["DELETE"])
def delete_user_preferences(user_id):
    
    # Delete preferences for a specific user.
    
    user_pref = UserPreferences.query.filter_by(user_id=user_id).first()
    if not user_pref:
        return jsonify({"error": "User preferences not found."}), 404
    
    db.session.delete(user_pref.supplements) if user_pref.supplements else None
    db.session.delete(user_pref.shoe_type)
    db.session.delete(user_pref.injuries)
    
    db.session.delete(user_pref)  # Delete the user preferences record itself
    db.session.commit()
    
    return jsonify({"message": "User preferences deleted successfully."}), 200

# End of the user preferences part.

if __name__ == '__main__':
    app.run(debug=True)
