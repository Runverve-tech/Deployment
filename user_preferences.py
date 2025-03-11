from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from datetime import datetime
import os
from dotenv import load_dotenv
from flask_migrate import Migrate
import pandas as pd
import enum
from sqlalchemy.dialects.postgresql import ENUM  # Use this for PostgreSQL
from sqlalchemy import Enum  # Use this for other databases


# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Load database URI directly from the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
# Disable modification tracking overhead
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    user_sk = db.Column(db.Integer, db.ForeignKey(
        'users.user_sk'), primary_key=True)
    token = db.Column(db.String(255), nullable=False)

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
    athlete_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'))
    name = db.Column(db.String(255))
    distance = db.Column(db.Float)
    moving_time = db.Column(db.Integer)
    elapsed_time = db.Column(db.Integer)
    total_elevation_gain = db.Column(db.Float)
    type = db.Column(db.String(50))
    start_date = db.Column(db.DateTime)
    description = db.Column(db.Text)
    calories = db.Column(db.Float)

# Define the User Preferences model

class SupplementsB(db.Model):
    __tablename__ = 'supplements_c'
    # Enum for supplement_form
    class SupplementFormEnum(str, enum.Enum):
        TABLET = "Tab"
        POWDER = "Powder"
        LIQUID = "Liquid"
    supplement_id = db.Column(db.Integer, primary_key=True)
    supplement_name = db.Column(db.String(100), nullable=False)
    supplement_type = db.Column(db.String(100), nullable=False)
    supplement_form = db.Column(
    Enum(SupplementFormEnum, name="supplement_form_enum"),
    nullable=False
    )
    supplement_serving_size = db.Column(db.String(50), nullable=False)  # Example: "5g", "1 scoop"
    supplement_serves_per_product = db.Column(db.Integer, nullable=False)  # Number of serves per product
    supplement_price = db.Column(db.Float, nullable=False)  # Price in decimal format
    supplement_use_or_benefit = db.Column(db.String(200), nullable=False)  # Purpose of the supplement
    supplement_recommended_usage = db.Column(db.String(200), nullable=False)  # Example: "2 times daily after meals"

    
    
class ShoeTypeB(db.Model):
    __tablename__ = 'shoetype_e'
     # Enum values for gender_category
    class GenderCategoryEnum(str, enum.Enum):
        MEN = "Men"
        WOMEN = "Women"
        UNISEX = "Unisex"

    # Enum values for shoe_type
    class ShoeTypeEnum(str, enum.Enum):
        NEUTRAL = "Neutral"
        STABILITY = "Stability"
        CUSHION = "Cushion"
    shoe_id = db.Column(db.Integer, primary_key=True)
    shoe_model = db.Column(db.String, nullable=False)
    shoe_brand = db.Column(db.String, nullable=False)
    shoe_color = db.Column(db.String, nullable=False)
    shoe_price = db.Column(db.Float, nullable=False)
    shoe_mileage = db.Column(db.Float, nullable=False, default=0.0)
    shoe_gender_category = db.Column(
        Enum(GenderCategoryEnum, name="gender_category_enum"),
        nullable=False
    )
    shoe_type = db.Column(
        Enum(ShoeTypeEnum, name="shoe_type_enum"),
        nullable=False
    )
    
class InjuriesB(db.Model):
    __tablename__ = 'injuries_b'
    injury_id = db.Column(db.Integer, primary_key=True)
    injury_name = db.Column(db.String, nullable=False)
    injury_description = db.Column(db.String, nullable=False)
    
class RunningSurface(db.Model):
    __tablename__ = 'running_surface'
    running_surface_id = db.Column(db.Integer, primary_key=True)
    running_surface_name = db.Column(db.String, nullable=False)
    
class UserRunningSurface(db.Model):
    __tablename__ = 'user_running_surface'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'), primary_key=False)
    running_surface_id = db.Column(db.Integer, db.ForeignKey('running_surface.running_surface_id', primary_key=False))    
    
class UserShoeType(db.Model):
    __tablename__ = 'user_shoetype_c'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'), primary_key=False)
    shoe_id = db.Column(db.Integer, db.ForeignKey('shoetype_e.shoe_id', primary_key=False))    

class UserSupplement(db.Model):
    __tablename__ = 'user_supplements_b'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'), primary_key=False)
    supplement_id = db.Column(db.Integer, db.ForeignKey('supplements_c.supplement_id'), primary_key=False)

class UserInjury(db.Model):
    __tablename__ = 'user_injuries_c'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_sk'), primary_key=False)
    injury_id = db.Column(db.Integer, db.ForeignKey('injuries_b.injury_id'), primary_key=False)
    
    
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


# User Preferences - Supplements

@app.route("/user/preferences/<int:user_id>/supplements", methods=["GET"])
def get_user_supplements(user_id):
    user_supplements = UserSupplement.query.filter_by(user_id=user_id).all()
    

    supplements_data = [
        {
            "supplement_id":supp.supplement_id,
            "supplement_name": SupplementsB.query.get(supp.supplement_id).supplement_name,
            "supplement_type": SupplementsB.query.get(supp.supplement_id).supplement_type,
            "supplement_form": SupplementsB.query.get(supp.supplement_id).supplement_form,
            "supplement_serving_size": SupplementsB.query.get(supp.supplement_id).supplement_serving_size,
            "supplement_serves_per_product": SupplementsB.query.get(supp.supplement_id).supplement_serves_per_product,
            "supplement_price": SupplementsB.query.get(supp.supplement_id).supplement_price,
            "supplement_use_or_benefit": SupplementsB.query.get(supp.supplement_id).supplement_use_or_benefit,
            "supplement_recommended_usage": SupplementsB.query.get(supp.supplement_id).supplement_recommended_usage
        }
        for supp in user_supplements
    ]
    
    return jsonify({"supplements": supplements_data}), 200

@app.route("/user/preferences/<int:user_id>/supplements", methods=["PUT"])
def update_user_supplements(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    if "supplements" in data:
        UserSupplement.query.filter_by(user_id=user_id).delete()
        supplements = [
            UserSupplement(user_id=user_id, supplement_id=item["supplement_id"])
            for item in data["supplements"]
        ]
    db.session.add_all(supplements)
    db.session.commit()
    return jsonify({"message": "Preferences updated successfully."}), 200


# User Preferences - ShoeType

@app.route("/user/preferences/<int:user_id>/shoetype", methods=["GET"])
def get_user_shoetype(user_id):
    user_shoe_types = UserShoeType.query.filter_by(user_id=user_id).all()
    

    shoe_types_data = [
        {
            "shoe_id":shoe.shoe_id,
            "shoe_model": ShoeTypeB.query.get(shoe.shoe_id).shoe_model,
            "shoe_brand": ShoeTypeB.query.get(shoe.shoe_id).shoe_brand,
            "shoe_color": ShoeTypeB.query.get(shoe.shoe_id).shoe_color,
            "shoe_price": ShoeTypeB.query.get(shoe.shoe_id).shoe_price,
            "shoe_mileage": ShoeTypeB.query.get(shoe.shoe_id).shoe_mileage,
            "shoe_gender_category": ShoeTypeB.query.get(shoe.shoe_id).shoe_gender_category,
            "shoe_type": ShoeTypeB.query.get(shoe.shoe_id).shoe_type
        }
        for shoe in user_shoe_types
    ]
    
    return jsonify({"shoetype": shoe_types_data}), 200

@app.route("/user/preferences/<int:user_id>/shoetype", methods=["PUT"])
def update_user_shoetype(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    if "shoe_type" in data:
        UserShoeType.query.filter_by(user_id=user_id).delete()
        shoe_types = [
            UserShoeType(user_id=user_id, shoe_id=item["shoe_id"])
            for item in data["shoe_type"]
        ]
    db.session.add_all(shoe_types)
    db.session.commit()
    return jsonify({"message": "Preferences updated successfully."}), 200


# User Preferences - Injuries

@app.route("/user/preferences/<int:user_id>/injuries", methods=["GET"])
def get_user_injuries(user_id):
    
    user_injuries = UserInjury.query.filter_by(user_id=user_id).all()
    

    injuries_data = [
        {
            "injury_id":injury.injury_id,
            "injury_name": InjuriesB.query.get(injury.injury_id).injury_name
            
            
        }
        for injury in user_injuries
    ]
    return jsonify({"injuries": injuries_data}), 200
    
@app.route("/user/preferences/<int:user_id>/injuries", methods=["PUT"])
def update_user_injuries(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    if "injuries" in data:
        UserInjury.query.filter_by(user_id=user_id).delete()
        injuries = [
            UserInjury(
                user_id=user_id,
                injury_id=item["injury_id"]
                
            )
            for item in data["injuries"]
        ]
    db.session.add_all(injuries)
    db.session.commit()
    return jsonify({"message": "Preferences updated successfully."}), 200


# User Preferences - Running Surface

@app.route("/user/preferences/<int:user_id>/running_surface", methods=["PUT"])
def update_user_running_surface(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    if "running_surface" in data:
        UserRunningSurface.query.filter_by(user_id=user_id).delete()
        running_surfaces = [
            
            UserRunningSurface(user_id=user_id, running_surface_id=item["running_surface_id"])
            for item in data["running_surface"]
        ]
    db.session.add_all(running_surfaces)
    db.session.commit()
    return jsonify({"message": "Preferences updated successfully."}), 200

@app.route("/user/preferences/<int:user_id>/running_surface", methods=["GET"])
def get_user_running_surface(user_id):
    user_running_surfaces = UserRunningSurface.query.filter_by(user_id=user_id).all()

    running_surfaces_data = [
        {
        "running_surface_id":rs.running_surface_id,
        "running_surface_name":RunningSurface.query.get(rs.running_surface_id).running_surface_name
        }
        for rs in user_running_surfaces
    ]
    
    return jsonify({"running_surface": running_surfaces_data}), 200


# Route to set or update user preferences
@app.route("/user/preferences/<int:user_id>", methods=["POST"])
def set_user_preferences(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    required_fields = ["supplements", "shoe_type", "injuries", "running_surface"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
        
    
    # Adding Supplements
    supplements = [
        UserSupplement(user_id=user_id, supplement_id=item["supplement_id"])
        for item in data["supplements"]
    ]
    
    # Adding Shoe Types
    shoe_types = [
        UserShoeType(user_id=user_id, shoe_id=item["shoe_id"])
        for item in data["shoe_type"]
    ]

    # Adding Injuries
    injuries = [
        UserInjury(
            user_id=user_id,
            injury_id=item["injury_id"]
            
        )
        for item in data["injuries"]
    ]

    # Adding Running Surfaces
    running_surfaces = [
        UserRunningSurface(user_id=user_id, running_surface_id=item["running_surface_id"])
        for item in data["running_surface"]
    ]

    db.session.add_all(supplements + shoe_types + injuries + running_surfaces)
    db.session.commit()

    return jsonify({"message": "Preferences saved successfully."}), 200

# Route to retrieve user preferences
@app.route("/user/preferences/<int:user_id>", methods=["GET"])
def get_user_preferences(user_id):
    user_supplements = UserSupplement.query.filter_by(user_id=user_id).all()
    user_shoe_types = UserShoeType.query.filter_by(user_id=user_id).all()
    user_injuries = UserInjury.query.filter_by(user_id=user_id).all()
    user_running_surfaces = UserRunningSurface.query.filter_by(user_id=user_id).all()

    supplements_data = [
        {
            "supplement_id":supp.supplement_id,
            "supplement_name": SupplementsB.query.get(supp.supplement_id).supplement_name,
            "supplement_type": SupplementsB.query.get(supp.supplement_id).supplement_type,
            "supplement_form": SupplementsB.query.get(supp.supplement_id).supplement_form,
            "supplement_serving_size": SupplementsB.query.get(supp.supplement_id).supplement_serving_size,
            "supplement_serves_per_product": SupplementsB.query.get(supp.supplement_id).supplement_serves_per_product,
            "supplement_price": SupplementsB.query.get(supp.supplement_id).supplement_price,
            "supplement_use_or_benefit": SupplementsB.query.get(supp.supplement_id).supplement_use_or_benefit,
            "supplement_recommended_usage": SupplementsB.query.get(supp.supplement_id).supplement_recommended_usage
        }
        for supp in user_supplements
    ]

    shoe_types_data = [
        {
            "shoe_id":shoe.shoe_id,
            "shoe_model": ShoeTypeB.query.get(shoe.shoe_id).shoe_model,
            "shoe_brand": ShoeTypeB.query.get(shoe.shoe_id).shoe_brand,
            "shoe_color": ShoeTypeB.query.get(shoe.shoe_id).shoe_color,
            "shoe_price": ShoeTypeB.query.get(shoe.shoe_id).shoe_price,
            "shoe_mileage": ShoeTypeB.query.get(shoe.shoe_id).shoe_mileage,
            "shoe_gender_category": ShoeTypeB.query.get(shoe.shoe_id).shoe_gender_category,
            "shoe_type": ShoeTypeB.query.get(shoe.shoe_id).shoe_type
        }
        for shoe in user_shoe_types
    ]

    injuries_data = [
        {
            "injury_id":injury.injury_id,
            "injury_name": InjuriesB.query.get(injury.injury_id).injury_name
            
            
        }
        for injury in user_injuries
    ]

    running_surfaces_data = [
        {
        "running_surface_id":rs.running_surface_id,
        "running_surface_name":RunningSurface.query.get(rs.running_surface_id).running_surface_name
        }
        for rs in user_running_surfaces
    ]

    response = {
        "user_id": user_id,
        "supplements": supplements_data,
        "shoe_type": shoe_types_data,
        "injuries": injuries_data,
        "running_surface": running_surfaces_data
    }

    return jsonify({"preferences": response}), 200

# Route to modify user preferences
@app.route("/user/preferences/<int:user_id>", methods=["PUT"])
def modify_user_preferences(user_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    
    

    if "supplements" in data:
        UserSupplement.query.filter_by(user_id=user_id).delete()
        supplements = [
            UserSupplement(user_id=user_id, supplement_id=item["supplement_id"])
            for item in data["supplements"]
        ]
        db.session.add_all(supplements)

    if "shoe_type" in data:
        UserShoeType.query.filter_by(user_id=user_id).delete()
        shoe_types = [
            UserShoeType(user_id=user_id, shoe_id=item["shoe_id"])
            for item in data["shoe_type"]
        ]
        db.session.add_all(shoe_types)

    if "injuries" in data:
        UserInjury.query.filter_by(user_id=user_id).delete()
        injuries = [
            UserInjury(
                user_id=user_id,
                injury_id=item["injury_id"]
                
            )
            for item in data["injuries"]
        ]
        db.session.add_all(injuries)

    if "running_surface" in data:
        UserRunningSurface.query.filter_by(user_id=user_id).delete()
        running_surfaces = [
            UserRunningSurface(user_id=user_id, running_surface_id=item["running_surface_id"])
            for item in data["running_surface"]
        ]
        db.session.add_all(running_surfaces)

    db.session.commit()
    return jsonify({"message": "Preferences modified successfully."}), 200

# Route to delete user preferences
@app.route("/user/preferences/<int:user_id>", methods=["DELETE"])
def delete_user_preferences(user_id):
    UserSupplement.query.filter_by(user_id=user_id).delete()
    UserShoeType.query.filter_by(user_id=user_id).delete()
    UserInjury.query.filter_by(user_id=user_id).delete()
    UserRunningSurface.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return jsonify({"message": "User preferences deleted successfully."}), 200


# Master data CRUD operations
@app.route("/masterdata/shoetype", methods=["POST"])
def set_shoe_type():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    shoetype = ShoeTypeB(
        shoe_model=data["shoe_model"],
        shoe_brand=data["shoe_brand"],
        shoe_color=data.get("shoe_color"),  # Optional fields
        shoe_price=data.get("shoe_price"),
        shoe_mileage=data.get("shoe_mileage"),
        shoe_gender_category=data.get("shoe_gender_category"),  # New field
        shoe_type=data.get("shoe_type")  # New field
    )
    db.session.add(shoetype)
    db.session.commit()
    return jsonify({"message": "Shoe type added successfully."}), 201

@app.route("/masterdata/shoetype", methods=["GET"])
def get_shoe_types():
    shoe_types = ShoeTypeB.query.all()
    return jsonify([{"shoe_id": s.shoe_id, "shoe_model": s.shoe_model, "shoe_brand": s.shoe_brand,
        "shoe_color": s.shoe_color,
        "shoe_price": s.shoe_price,
        "shoe_mileage": s.shoe_mileage,
        "shoe_gender_category": s.shoe_gender_category,
        "shoe_type": s.shoe_type} for s in shoe_types])

@app.route("/masterdata/shoetype/<int:shoe_id>", methods=["PUT"])
def update_shoe_type(shoe_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    shoe_type = ShoeTypeB.query.get(shoe_id)
    if not shoe_type:
        return jsonify({"error": "Shoe type not found."}), 404

    shoe_type.shoe_model = data.get("shoe_model", shoe_type.shoe_model)
    shoe_type.shoe_brand = data.get("shoe_brand", shoe_type.shoe_brand)
    shoe_type.shoe_color = data.get("shoe_color", shoe_type.shoe_color)
    shoe_type.shoe_price = data.get("shoe_price", shoe_type.shoe_price)
    shoe_type.shoe_mileage = data.get("shoe_mileage", shoe_type.shoe_mileage)
    shoe_type.shoe_gender_category = data.get("shoe_gender_category", shoe_type.shoe_gender_category)
    shoe_type.shoe_type = data.get("shoe_type", shoe_type.shoe_type)
    db.session.commit()

    return jsonify({"message": "Shoe type updated successfully."}), 200

@app.route("/masterdata/shoetype/<int:shoe_id>", methods=["DELETE"])
def delete_shoe_type(shoe_id):
    shoe_type = ShoeTypeB.query.get(shoe_id)
    if not shoe_type:
        return jsonify({"error": "Shoe type not found."}), 404

    db.session.delete(shoe_type)
    db.session.commit()

    return jsonify({"message": "Shoe type deleted successfully."}), 200

@app.route("/masterdata/supplements", methods=["POST"])
def set_supplements():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    supplement = SupplementsB(
        supplement_name=data["supplement_name"],
        supplement_type=data["supplement_type"],
        supplement_form=data.get("supplement_form"),  # Optional field
        supplement_serving_size=data.get("supplement_serving_size"),
        supplement_serves_per_product=data.get("supplement_serves_per_product"),  # Optional field
        supplement_price=data.get("supplement_price"),
        supplement_use_or_benefit=data.get("supplement_use_or_benefit"),  # Optional field
        supplement_recommended_usage=data.get("supplement_recommended_usage")  # Optional field
    )
    db.session.add(supplement)
    db.session.commit()
    return jsonify({"message": "Supplement added successfully."}), 201

@app.route("/masterdata/supplements", methods=["GET"])
def get_supplements():
    supplements = SupplementsB.query.all()
    return jsonify([{"supplement_id": s.supplement_id, "supplement_name": s.supplement_name, "supplement_type": s.supplement_type,
        "supplement_form": s.supplement_form,
        "supplement_serving_size": s.supplement_serving_size,
        "supplement_serves_per_product": s.supplement_serves_per_product,
        "supplement_price": s.supplement_price,
        "supplement_use_or_benefit": s.supplement_use_or_benefit,
        "supplement_recommended_usage": s.supplement_recommended_usage} for s in supplements])

@app.route("/masterdata/supplements/<int:supplement_id>", methods=["PUT"])
def update_supplement(supplement_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    supplement = SupplementsB.query.get(supplement_id)
    if not supplement:
        return jsonify({"error": "Supplement not found."}), 404

    supplement.supplement_name = data.get("supplement_name", supplement.supplement_name)
    supplement.supplement_type = data.get("supplement_type", supplement.supplement_type)
    supplement.supplement_form = data.get("supplement_form", supplement.supplement_form)
    supplement.supplement_serving_size = data.get("supplement_serving_size", supplement.supplement_serving_size)
    supplement.supplement_serves_per_product = data.get("supplement_serves_per_product", supplement.supplement_serves_per_product)
    supplement.supplement_price = data.get("supplement_price", supplement.supplement_price)
    supplement.supplement_use_or_benefit = data.get("supplement_use_or_benefit", supplement.supplement_use_or_benefit)
    supplement.supplement_recommended_usage = data.get("supplement_recommended_usage", supplement.supplement_recommended_usage)
    db.session.commit()

    return jsonify({"message": "Supplement updated successfully."}), 200

@app.route("/masterdata/supplements/<int:supplement_id>", methods=["DELETE"])
def delete_supplement(supplement_id):
    supplement = SupplementsB.query.get(supplement_id)
    if not supplement:
        return jsonify({"error": "Supplement not found."}), 404

    db.session.delete(supplement)
    db.session.commit()

    return jsonify({"message": "Supplement deleted successfully."}), 200

    
@app.route("/masterdata/injuries", methods=["POST"])
def set_injuries():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    injury = InjuriesB(
        injury_name = data["injury_name"],
        injury_description = data["injury_description"]
    )
    db.session.add(injury)
    db.session.commit()
    return jsonify({"message": "Injury added successfully."}), 201
    
@app.route("/masterdata/injuries", methods=["GET"])
def get_injuries():
    injuries = InjuriesB.query.all()
    return jsonify([{"injury_id": s.injury_id, "injury_name": s.injury_name, "injury_description": s.injury_description} for s in injuries])

@app.route("/masterdata/injuries/<int:injury_id>", methods=["PUT"])
def update_injuries(injury_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    injury = InjuriesB.query.get(injury_id)
    if not injury:
        return jsonify({"error": "injury not found."}), 404

    injury.injury_name = data.get("injury_name", injury.injury_name)
    injury.injury_description = data.get("injury_description", injury.injury_description)
    db.session.commit()

    return jsonify({"message": "injury updated successfully."}), 200

@app.route("/masterdata/injuries/<int:injury_id>", methods=["DELETE"])
def delete_injury(injury_id):
    injury = InjuriesB.query.get(injury_id)
    if not injury:
        return jsonify({"error": "injury not found."}), 404

    db.session.delete(injury)
    db.session.commit()

    return jsonify({"message": "injury deleted successfully."}), 200

    
@app.route("/masterdata/running_surface", methods=["POST"])
def set_running_surface():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400
    running_surface = RunningSurface(
        running_surface_name = data.get("running_surface_name")
    )
    db.session.add(running_surface)
    db.session.commit()
    return jsonify({"message": "Running Surface added successfully."}), 201
    
@app.route("/masterdata/running_surface", methods=["GET"])
def get_running_surface():
    running_surface = RunningSurface.query.all()
    return jsonify([{"running_surface_id": s.running_surface_id, "running_surface_name": s.running_surface_name} for s in running_surface])

@app.route("/masterdata/running_surface/<int:running_surface_id>", methods=["PUT"])
def update_running_surface(running_surface_id):
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input. JSON data is required."}), 400

    running_surface = RunningSurface.query.get(running_surface_id)
    if not running_surface:
        return jsonify({"error": "Running Surface not found."}), 404

    running_surface.running_surface_name = data.get("running_surface_name", running_surface.running_surface_name)
    db.session.commit()

    return jsonify({"message": "Running Surface updated successfully."}), 200

@app.route("/masterdata/running_surface/<int:running_surface_id>", methods=["DELETE"])
def delete_running_surface(running_surface_id):
    running_surface = RunningSurface.query.get(running_surface_id)
    if not running_surface:
        return jsonify({"error": "Running Surface not found."}), 404

    db.session.delete(running_surface)
    db.session.commit()

    return jsonify({"message": "Running Surface deleted successfully."}), 200



if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=False)
 