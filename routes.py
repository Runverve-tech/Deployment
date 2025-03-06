from flask import Flask, redirect, url_for, request, jsonify, g
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import requests
from models import User, UserToken, Activity, StravaMetric
from app import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import os


app = Flask(__name__)

# Google and Strava configuration

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Google and Strava configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

STRAVA_CLIENT_ID = os.getenv('STRAVA_CLIENT_ID')
STRAVA_CLIENT_SECRET = os.getenv('STRAVA_CLIENT_SECRET')
STRAVA_REDIRECT_URI = os.getenv('STRAVA_REDIRECT_URI')


def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def decode_jwt(token):
    try:
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        user_id = decode_jwt(token)
        if not user_id:
            return jsonify({"error": "Token is invalid!"}), 401
        g.user_id = user_id
        return f(*args, **kwargs)
    return decorated_function


def register_routes(app, db):
    @app.route('/')
    def index():
        return "Welcome to Runverve!"

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()

        # Extracting data from the request
        username = data.get('username')
        email_id = data.get('email_id')
        password = data.get('password')
        gender = data.get('gender')
        date_of_birth = data.get('DOB')
        height = data.get('height')
        weight = data.get('weight')
        experience_level = data.get('experience_level')
        distance_goal = data.get('distance_goal')
        mobile_no = data.get('mobile_no')

        # Input validation
        if not username or not email_id or not password:
            return jsonify({"error": "Username, email, and password are required!"}), 400

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email_id).first()
        if existing_user:
            return jsonify({"error": "Email is already registered!"}), 400

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new User object
        new_user = User(
            username=username,
            email=email_id,
            password=hashed_password,
            gender=gender,
            date_of_birth=date_of_birth,
            height=height,
            weight=weight,
            experience_level=experience_level,
            distance_goal=distance_goal,
            mobile_no=mobile_no,
        )

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        # Generate JWT token
        token = generate_jwt(new_user.user_sk)

        return jsonify({"message": "User registered successfully!", "token": token, "user": {
            "id": new_user.user_sk,
            "username": new_user.username,
            "email": new_user.email
        }}), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required!"}), 400

        # Check if the user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Invalid email or password!"}), 401

        # Verify the password
        if not check_password_hash(user.password, password):
            return jsonify({"error": "Invalid email or password!"}), 401

        # Generate JWT token
        token = generate_jwt(user.user_sk)

        return jsonify({"message": "Logged in successfully!", "token": token, "user": {
            "id": user.user_sk,
            "username": user.username,
            "email": user.email
        }}), 200

    @app.route('/auth/google/login')
    def google_login():
        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=["https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=url_for('google_callback', _external=True)
        )
        authorization_url, state = flow.authorization_url(prompt='consent')
        return redirect(authorization_url)

    @app.route('/auth/google/callback')
    def google_callback():
        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=["https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=url_for('google_callback', _external=True)
        )
        flow.fetch_token(authorization_response=request.url)

        credentials = flow.credentials

        user_info = fetch_google_user_info(credentials)

        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(
                username=user_info.get('name'),
                email=user_info['email'],
                google_id=user_info['sub']
            )
            db.session.add(user)
            db.session.commit()

        token = generate_jwt(user.user_sk)

        return jsonify({
            "message": "Successfully logged in with Google!",
            "token": token,
            "user": {
                "id": user.user_sk,
                "username": user.username,
                "email": user.email
            }
        })

    @app.route("/auth/strava/login")
    @token_required
    def strava_login():
        strava_auth_url = (
            f"https://www.strava.com/oauth/authorize?"
            f"client_id={STRAVA_CLIENT_ID}&response_type=code&"
            f"redirect_uri={STRAVA_REDIRECT_URI}&"
            f"scope=read,activity:read_all,profile:read_all&approval_prompt=auto"
        )
        return redirect(strava_auth_url)

    @app.route('/auth/strava/callback')
    @token_required
    def strava_callback():
        auth_code = request.args.get('code')
        if not auth_code:
            return jsonify({"error": "Authorization code missing!"}), 400

        token_response = requests.post(
            "https://www.strava.com/oauth/token",
            data={
                "client_id": STRAVA_CLIENT_ID,
                "client_secret": STRAVA_CLIENT_SECRET,
                "code": auth_code,
                "grant_type": "authorization_code"
            }
        ).json()

        if "access_token" not in token_response:
            return jsonify({"error": "Failed to get access token from Strava!"}), 400

        strava_id = token_response.get("athlete", {}).get("id")
        if not strava_id:
            return jsonify({"error": "Failed to fetch athlete information!"}), 400

        user = User.query.get(g.user_id)
        if not user:
            return jsonify({"error": "User not found!"}), 404

        user.strava_id = strava_id
        db.session.commit()

        strava_access_token = token_response['access_token']
        strava_refresh_token = token_response.get('refresh_token')
        token_expires_at = token_response.get('expires_at')

        strava_token = UserToken.query.filter_by(
            user_sk=user.user_sk, provider='strava').first()
        if not strava_token:
            strava_token = UserToken(
                user_sk=user.user_sk,
                provider='strava',
                access_token=strava_access_token,
                refresh_token=strava_refresh_token,
                token_expires_at=datetime.fromtimestamp(token_expires_at)
            )
            db.session.add(strava_token)
            db.session.commit()
        else:
            strava_token.access_token = strava_access_token
            strava_token.refresh_token = strava_refresh_token
            strava_token.token_expires_at = datetime.fromtimestamp(
                token_expires_at)
            db.session.commit()

        return jsonify({
            "message": "Strava account successfully linked!",
            "user": {
                "id": user.user_sk,
                "username": user.username,
                "strava_id": user.strava_id
            }
        })

    @app.route("/strava/activities", methods=["GET"])
    @token_required
    def get_strava_activities():
        user = User.query.get(g.user_id)
        if not user or not user.strava_id:
            return jsonify({"error": "User or Strava account not linked!"}), 404

        token = UserToken.query.filter_by(
            user_sk=user.user_sk, provider='strava').first()
        if not token:
            return jsonify({"error": "Strava access token not found!"}), 400

        # Check if Strava token needs to be refreshed
        token = refresh_strava_token_if_needed(token)

        activities_data = fetch_strava_activities(token.access_token)
        if "error" in activities_data:
            return jsonify(activities_data), 400

        for activity_data in activities_data:
            existing_activity = Activity.query.filter_by(
                strava_activity_id=str(activity_data['id'])).first()
            if not existing_activity:
                new_activity = Activity(
                    user_sk=user.user_sk,
                    strava_activity_id=activity_data['id'],
                    name=activity_data['name'],
                    distance=activity_data['distance'],
                    moving_time=activity_data['moving_time'],
                    elapsed_time=activity_data['elapsed_time'],
                    total_elevation_gain=activity_data['total_elevation_gain'],
                    type=activity_data['type'],
                    start_date=activity_data['start_date'],
                    description=activity_data.get('description', ''),
                )
                db.session.add(new_activity)
                db.session.commit()

        return jsonify({"message": "Activities fetched and stored!"})

    @app.route('/strava/metrics/<int:activity_id>', methods=['GET'])
    @token_required
    def get_strava_metrics(activity_id):
        user = User.query.get(g.user_id)
        if not user or not user.strava_id:
            return jsonify({"error": "User or Strava account not linked!"}), 404

        token = UserToken.query.filter_by(
            user_sk=user.user_sk, provider='strava').first()
        if not token:
            return jsonify({"error": "Strava access token not found!"}), 400

        # Check if Strava token needs to be refreshed
        token = refresh_strava_token_if_needed(token)

        metrics_data = fetch_strava_metrics(token.access_token, activity_id)
        if "error" in metrics_data:
            return jsonify(metrics_data), 400

        activity = Activity.query.get(activity_id)
        if not activity:
            return jsonify({"error": "Activity not found!"}), 404

        existing_metrics = StravaMetric.query.filter_by(
            activity_id=activity_id).first()
        if not existing_metrics:
            new_metrics = StravaMetric(
                user_sk=user.user_sk,
                activity_id=activity_id,
                pace=metrics_data.get('pace', None),
                heart_rate=metrics_data.get('heart_rate', None),
                cadence=metrics_data.get('cadence', None),
                power=metrics_data.get('power', None)
            )
            db.session.add(new_metrics)
            db.session.commit()

        return jsonify({"message": "Metrics fetched and stored!"})

    @app.route('/strava/user-profile', methods=['GET'])
    @token_required
    def get_strava_user_profile():
        user = User.query.get(g.user_id)
        if not user or not user.strava_id:
            return jsonify({"error": "User or Strava account not linked!"}), 404

        token = UserToken.query.filter_by(
            user_sk=user.user_sk, provider='strava').first()
        if not token:
            return jsonify({"error": "Strava access token not found!"}), 400

        # Check if Strava token needs to be refreshed
        token = refresh_strava_token_if_needed(token)

        profile_data = fetch_strava_user_profile(token.access_token)
        if "error" in profile_data:
            return jsonify(profile_data), 400

        return jsonify(profile_data)


def fetch_strava_user_profile(access_token):
    url = "https://www.strava.com/api/v3/athlete"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch Strava user profile!"}


def fetch_strava_activities(access_token):
    url = "https://www.strava.com/api/v3/athlete/activities"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch Strava activities!"}


def fetch_strava_metrics(access_token, activity_id):
    url = f"https://www.strava.com/api/v3/activities/{activity_id}/streams"
    headers = {"Authorization": f"Bearer {access_token}"}

    params = {"keys[]": "heartrate,cadence,power,pace",
              "key_by_type": "true"}

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch Strava activity metrics!"}


def fetch_google_user_info(credentials):
    response = requests.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        headers={'Authorization': f'Bearer {credentials.token}'}
    )
    return response.json()


def refresh_strava_token_if_needed(token):
    if token.token_expires_at and token.token_expires_at < datetime.utcnow():
        response = requests.post(
            "https://www.strava.com/oauth/token",
            data={
                "client_id": STRAVA_CLIENT_ID,
                "client_secret": STRAVA_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": token.refresh_token
            }
        ).json()

        if "access_token" in response:
            token.access_token = response.get("access_token")
            token.refresh_token = response.get("refresh_token")
            token.token_expires_at = datetime.fromtimestamp(
                response.get("expires_at"))
            db.session.commit()

    return token


if __name__ == '__main__':
    app.run(debug=True)
