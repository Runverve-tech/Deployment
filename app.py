from flask import Flask, request, session, jsonify, redirect, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import datetime as dt
import os
from dotenv import load_dotenv
import requests
import json
import subprocess
import platform
import re
from flask_migrate import Migrate
from werkzeug.utils import secure_filename

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

app.secret_key = os.getenv('SERVER_SECRET_KEY', 'ABCD')

# Load database URI directly from the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
# Disable modification tracking overhead
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload settings
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size 16MB

# API credentials
CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'CLIENT_SECRET'
REDIRECT_URI = 'http://localhost:5000/exchange_token'
GOOGLE_API_KEY = '<your api key>'

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    user_sk = db.Column(db.Integer, db.ForeignKey('users.user_sk'))
    platform = db.Column(db.String(100), nullable=False)
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
    type = db.Column(db.String(50))
    start_date = db.Column(db.DateTime, default=dt.date.today())
    description = db.Column(db.Text)
    calories = db.Column(db.Float, default=0.0)

# Define the Supplements model
class Supplements(db.Model):
    __tablename__ = 'supplements'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

# Define the ShoeType model
class ShoeType(db.Model):
    __tablename__ = 'shoe_type'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

# Define the Injuries model
class Injuries(db.Model):
    __tablename__ = 'injuries'
    id = db.Column(db.Integer, primary_key=True)
    tennis_elbow = db.Column(db.Boolean, default=False)
    muscle_strain = db.Column(db.Boolean, default=False)
    bicep_tendonitis = db.Column(db.Boolean, default=False)
    fracture = db.Column(db.Boolean, default=False)
    forearm_strain = db.Column(db.Boolean, default=False)

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

# Define the photo model
class Photo(db.Model):
    __tablename__ = 'photos'
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_sk = db.Column(db.Integer, db.ForeignKey('users.user_sk'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    photo_data = db.Column(db.LargeBinary, nullable=False)

# Define the SupplementPhoto model
class SupplementPhoto(db.Model):
    __tablename__ = 'supplement_photos'
    pic_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_sk = db.Column(db.Integer, db.ForeignKey('users.user_sk'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    supplement_type = db.Column(db.String(100), nullable=False)
    photo_data = db.Column(db.LargeBinary, nullable=False)

# Define the GeocodingResult model
class GeocodingResult(db.Model):
    __tablename__ = 'geocoding_results'
    id = db.Column(db.Integer, primary_key=True)
    formatted_address = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    place_id = db.Column(db.Text, nullable=False)
    types = db.Column(db.JSON, nullable=True)
    address_components = db.Column(db.JSON, nullable=True)
    plus_code = db.Column(db.JSON, nullable=True)
    viewport = db.Column(db.JSON, nullable=True)

# Define the UserInfo model
class UserInfo(db.Model):
    __tablename__ = 'user_info'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email_id = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    height = db.Column(db.Float, nullable=True)
    weight = db.Column(db.Float, nullable=True)
    experience_level = db.Column(db.String(50), nullable=True)
    distance_goal = db.Column(db.Float, nullable=True)
    preferences = db.Column(db.Text, nullable=True)
    mobile_no = db.Column(db.String(15), nullable=True)

# Define the InjuryReport model
class InjuryReport(db.Model):
    __tablename__ = 'injury_report'
    id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, db.ForeignKey('users.user_sk'), nullable=False)
    injury_id = db.Column(db.Integer, db.ForeignKey('injuries.id'), nullable=False)
    injury_location = db.Column(db.String(100), nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)

    injury = db.relationship('Injuries', backref='injury_reports')

# Define the HydrationLogs model
class HydrationLogs(db.Model):
    __tablename__ = 'hydration_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, nullable=False)  
    quantity = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Helper function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Home route
@app.route('/')
def home():
    # If an API object is defined elsewhere, uncommenting this might be appropriate
    # auth_url = api.generate_auth_url()
    # print(session.get('email'))
    # return redirect(auth_url)
    return "Welcome to the Runverve"

# Token exchange route
@app.route('/exchange_token')
def exchange_token():
    code = request.args.get('code')
    if code:
        # If an API object is defined elsewhere, uncommenting this might be appropriate
        # token_data = api.exchange_token(code)
        # if token_data:
        #     access_token = token_data.get("access_token")
        #     user_data = api.get_user_data(access_token) 
        #     user_sk = user_data.get("id")  
        #     user = User.query.filter_by(user_sk=user_sk).first()
        #     if user is None:
        #         user = User(
        #             user_sk=user_sk,
        #             username=user_data.get("username"),
        #             email=user_data.get("email") or "unknown@example.com"
        #         )
        #         db.session.add(user)
        #         db.session.commit()

        #     # Store `user_sk` in the session
        #     session['user_sk'] = user_sk

        #     return render_template('upload_photos.html', access_token=access_token)
        # else:
        #     return "Error exchanging code for token", 400
        return "Token exchange functionality not yet implemented", 501
    else:
        return "Error: No authorization code received", 400

# User creation route
@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created", "user_sk": new_user.user_sk}), 201

# Get users route
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{"user_sk": user.user_sk, "username": user.username, "email": user.email} for user in users])

# User preferences routes
@app.route("/user/preferences/<user_id>", methods=["POST"])
def set_user_preferences(user_id):
    """Set preferences for a specific user."""
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    
    required_fields = ["shoe_type", "injuries", "running_surface"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
        
    # Create records
    supplements_data = data.get("supplements")
    shoe_type_data = data["shoe_type"]
    injuries_data = data["injuries"]

    if supplements_data:
        supplements = Supplements(
            name=supplements_data["name"],
            model=supplements_data["model"],
            description=supplements_data["description"]
        )
        db.session.add(supplements)
        db.session.commit()
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

@app.route("/user/preferences/<user_id>", methods=["GET"])
def get_user_preferences(user_id):
    """Retrieve preferences for a specific user."""
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

@app.route("/user/preferences", methods=["GET"])
def get_all_user_preferences():
    """Retrieve preferences for all users."""
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
    """Modify preferences for a specific user."""
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    user_pref = UserPreferences.query.filter_by(user_id=user_id).first()
    if not user_pref:
        return jsonify({"error": "User preferences not found."}), 404

    # Update existing related records
    if "supplements" in data and user_pref.supplements:
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
    """Delete preferences for a specific user."""
    user_pref = UserPreferences.query.filter_by(user_id=user_id).first()
    if not user_pref:
        return jsonify({"error": "User preferences not found."}), 404
    
    db.session.delete(user_pref.supplements) if user_pref.supplements else None
    db.session.delete(user_pref.shoe_type)
    db.session.delete(user_pref.injuries)
    
    db.session.delete(user_pref)  # Delete the user preferences record itself
    db.session.commit()
    
    return jsonify({"message": "User preferences deleted successfully."}), 200

# Photo upload routes
@app.route('/user/photos', methods=['POST'])
def upload_photos():
    if 'user_sk' not in session:
        return jsonify({"message": "User not logged in"}), 401

    user_sk = session['user_sk']  
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        photo_data = file.read()
        filename = secure_filename(file.filename)
        new_photo = Photo(
            user_sk=user_sk,
            filename=filename,
            photo_data=photo_data
        )
        db.session.add(new_photo)
        db.session.commit()

        return jsonify({"message": "File successfully uploaded", "photo_id": new_photo.pid}), 201
    else:
        return jsonify({"message": "File type not allowed"}), 400

@app.route('/user/photos', methods=['GET'])
def render_photo_upload():
    """Render the photo upload page."""
    return render_template('upload_photos.html')

@app.route('/user/photos/<int:photo_id>', methods=['GET'])
def view_photo(photo_id):
    photo = Photo.query.get(photo_id)
    if not photo:
        return jsonify({"message": "Photo not found"}), 404
    
    mime_type = None
    if photo.filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
        mime_type = f"image/{photo.filename.rsplit('.', 1)[1].lower()}"

    if not mime_type:
        return jsonify({"message": "Unsupported file type"}), 400

    return Response(photo.photo_data, content_type=mime_type)

@app.route('/user/photos/<int:photo_id>', methods=['DELETE'])
def delete_photo(photo_id):
    photo = Photo.query.get(photo_id)
    if not photo:
        return jsonify({"message": "Photo not found"}), 404
    
    try:
        db.session.delete(photo)
        db.session.commit()
        return jsonify({"message": f"Photo with ID {photo_id} successfully deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting photo", "error": str(e)}), 500

# Supplement photo routes
@app.route('/user/supplements', methods=['POST'])
def upload_supplement_photo():
    """Allows users to upload photos of their supplements."""
    if 'user_sk' not in session:
        return jsonify({"message": "User not logged in"}), 401

    user_sk = session['user_sk']  # Retrieve user_sk from session

    if 'file' not in request.files or 'supplement_type' not in request.form:
        return jsonify({"message": "File and supplement type are required"}), 400

    file = request.files['file']
    supplement_type = request.form['supplement_type']

    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if file and allowed_file(file.filename):
        # Read the binary data and secure the filename
        photo_data = file.read()
        filename = secure_filename(file.filename)

        # Create and save the photo in the database
        new_photo = SupplementPhoto(
            user_sk=user_sk,
            filename=filename,
            supplement_type=supplement_type,
            photo_data=photo_data
        )
        db.session.add(new_photo)
        db.session.commit()

        return jsonify({"message": "File successfully uploaded", "pic_id": new_photo.pic_id}), 201
    else:
        return jsonify({"message": "File type not allowed"}), 400

@app.route('/user/supplements/<int:pic_id>', methods=['GET'])
def view_supplement_photo(pic_id):
    """Retrieve and display the uploaded supplement photo."""
    photo = SupplementPhoto.query.get(pic_id)
    if not photo:
        return jsonify({"message": "Photo not found"}), 404

    # Determine the MIME type based on file extension
    mime_type = None
    if photo.filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
        mime_type = f"image/{photo.filename.rsplit('.', 1)[1].lower()}"

    if not mime_type:
        return jsonify({"message": "Unsupported file type"}), 400

    return Response(photo.photo_data, content_type=mime_type)

@app.route('/user/supplements', methods=['GET'])
def render_supplement_photo_upload():
    """Render the supplement photo upload page."""
    return render_template('upload_supplements.html')

# Geocoding routes
@app.route('/geocode', methods=['POST'])
def geocode():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    
    # Implementation for creating a geocoding entry
    # This part needs to be updated to match the actual requirements
    
    return jsonify({"message": "Geocoding functionality not yet implemented"}), 501

@app.route('/geocode', methods=['GET'])
def get_geocoding_result():
    """Retrieve geocoding data by place_id, coordinates, or formatted address."""
 
    place_id = request.args.get('place_id')
    lat = request.args.get('lat', type=float)
    lng = request.args.get('lng', type=float)
    formatted_address = request.args.get('formatted_address')

    if place_id:
        result = GeocodingResult.query.filter_by(place_id=place_id).first()
    elif lat is not None and lng is not None:
        result = GeocodingResult.query.filter_by(latitude=lat, longitude=lng).first()
    elif formatted_address:
        result = GeocodingResult.query.filter_by(formatted_address=formatted_address).first()
    else:
        return jsonify({"error": "Please provide a place_id, latitude and longitude, or a formatted_address."}), 400

    if not result:
        return jsonify({"message": "No geocoding result found for the given input."}), 404

    return jsonify({
        "id": result.id,
        "formatted_address": result.formatted_address,
        "latitude": result.latitude,
        "longitude": result.longitude,
        "place_id": result.place_id,
        "types": result.types,
        "address_components": result.address_components,
        "plus_code": result.plus_code,
        "viewport": result.viewport
    }), 200

@app.route('/geocode/<int:id>', methods=['DELETE'])
def delete_address(id):
    """Delete an address by its ID."""
    geocode_entry = GeocodingResult.query.get(id)
    
    if not geocode_entry:
        return jsonify({"message": "Address not found"}), 404
    
    try:
        db.session.delete(geocode_entry)
        db.session.commit()
        return jsonify({"message": f"Address with ID {id} successfully deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting address", "error": str(e)}), 500

# Injury reporting routes
@app.route('/user/injuries', methods=['POST'])
def report_injury():
    data = request.get_json()

    user_sk = data.get('user_sk')
    injuries = data.get('injuries')

    if not user_sk:
        return jsonify({"error": "'user_sk' is required."}), 400

    if not injuries or not isinstance(injuries, list):
        return jsonify({"error": "'injuries' must be a list of injury objects."}), 400

    user = User.query.filter_by(user_sk=user_sk).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    response = []

    for injury_data in injuries:
        injury_id = injury_data.get('injury_id')
        injury_location = injury_data.get('injury_location')

        if not injury_id or not injury_location:
            response.append({"error": "Each injury must include 'injury_id' and 'injury_location'."})
            continue

        # Fetch injury details from the Injuries table
        injury = Injuries.query.filter_by(id=injury_id).first()
        if not injury:
            response.append({"error": f"Injury with id {injury_id} not found."})
            continue

        injury_report = InjuryReport(
            user_sk=user_sk,
            injury_id=injury_id,
            injury_location=injury_location
        )
        db.session.add(injury_report)

        response.append({
            "injury_id": injury_id,
            "injury_location": injury_location,
            "injury_type": {
                "tennis_elbow": injury.tennis_elbow,
                "muscle_strain": injury.muscle_strain,
                "bicep_tendonitis": injury.bicep_tendonitis,
                "fracture": injury.fracture,
                "forearm_strain": injury.forearm_strain
            },
            "status": "Injury report submitted successfully."
        })

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to save injury reports: {str(e)}"}), 500

    return jsonify(response), 200

# Hydration logging routes
@app.route('/user/hydration', methods=['POST'])
def log_hydration():
    data = request.get_json()
    
    user_sk = data.get('user_sk')
    quantity = data.get('quantity')
    
    if not user_sk:
        return jsonify({"error": "'user_sk' is required."}), 400
    
    if not quantity or not isinstance(quantity, int):
        return jsonify({"error": "'quantity' is required and must be an integer."}), 400
    
    hydration_log = HydrationLogs(user_sk=user_sk, quantity=quantity)
    db.session.add(hydration_log)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to log hydration: {str(e)}"}), 500
    
    return jsonify({
        "message": "Water intake logged successfully.",
        "user_sk": user_sk,
        "quantity": quantity
    }), 200

@app.route('/user/profile', methods=['GET'])
def get_user():
    """Retrieve a user profile by ID or username."""
    user_id = request.args.get('id', type=int)
    username = request.args.get('username', type=str)

    if user_id:
        user = UserInfo.query.get(user_id)
    elif username:
        user = UserInfo.query.filter_by(username=username).first()
    else:
        return jsonify({"message": "Please provide either 'id' or 'username' as a query parameter."}), 400

    if not user:
        return jsonify({"message": "User not found"}), 404

    user_data = {
        "username": user.username,
        "email_id": user.email_id,
        "gender": user.gender,
        "date_of_birth": user.date_of_birth,
        "height": user.height,
        "weight": user.weight,
        "experience_level": user.experience_level,
        "distance_goal": user.distance_goal,
        "preferences": user.preferences,
        "mobile_no": user.mobile_no
    }
    return jsonify(user_data), 200



@app.route('/user/profile', methods=['POST'])
def create_user_profile():
    """Create a new user profile."""
    data = request.json
    if not data:
        return jsonify({"message": "Invalid input"}), 400

    if UserInfo.query.filter_by(username=data.get('username')).first():
        return jsonify({"message": "Username already exists"}), 400
    if UserInfo.query.filter_by(email_id=data.get('email_id')).first():
        return jsonify({"message": "Email already exists"}), 400

    #Password must be at least 8 characters long, include a number, an uppercase letter, and a special character
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$' 
    if not re.match(password_regex, data.get('password')):
        return jsonify({"message": "Password must be at least 8 characters long, include a number, an uppercase letter, and a special character"}), 400

    try:
        height = float(data.get('height'))
        weight = float(data.get('weight'))
    
    except (ValueError, TypeError):
        return jsonify({"message": "Height and Weight and Number must be numeric"}), 400

    
    new_user = UserInfo(
        username=data.get('username'),
        email_id=data.get('email_id'),
        password=data.get('password'),
        gender=data.get('gender'),
        date_of_birth=data.get('date_of_birth'),
        height=height,
        weight=weight,
        experience_level=data.get('experience_level'),
        distance_goal=data.get('distance_goal'),
        preferences=data.get('preferences'),
        mobile_no=data.get('mobile_no')
    )

    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User profile created successfully"}), 201




@app.route('/user/profile/update', methods=['PUT'])
def update_user_profile():
    """Update a user profile by user ID."""
    user_id = request.args.get('id', type=int)
    user = UserInfo.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.json
    if 'username' in data:
        if UserInfo.query.filter_by(username=data['username']).first() and user.username != data['username']:
            return jsonify({"message": "Username already exists"}), 400
        user.username = data['username']
    
    if 'password' in data:
        if len(data['password']) < 8:
            return jsonify({"message": "Password must be at least 8 characters long"}), 400
        user.password = data['password']
    
    if 'height' in data:
        try:
            user.height = float(data['height'])
        except ValueError:
            return jsonify({"message": "Height must be a numeric value"}), 400
    
    if 'weight' in data:
        try:
            user.weight = float(data['weight'])
        except ValueError:
            return jsonify({"message": "Weight must be a numeric value"}), 400

    if 'experience_level' in data:
        user.experience_level = data['experience_level']
    
    if 'distance_goal' in data:
        try:
            user.distance_goal = float(data['distance_goal'])
        except ValueError:
            return jsonify({"message": "Distance goal must be a numeric value"}), 400

    if 'preferences' in data:
        user.preferences = data['preferences']
    
    if 'mobile_no' in data:
        if len(data['mobile_no']) != 10 or not data['mobile_no'].isdigit():
            return jsonify({"message": "Mobile number must be a 10-digit numeric value"}), 400
        user.mobile_no = data['mobile_no']

    db.session.commit()

    return jsonify({"message": "User profile updated successfully"}), 200

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000,debug=True)