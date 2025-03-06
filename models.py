from app import db


class User(db.Model):
    __tablename__ = 'users'

    user_sk = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    google_id = db.Column(db.String(255), unique=True)
    strava_id = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(512), nullable=True)  # New field
    gender = db.Column(db.String(10))
    date_of_birth = db.Column(db.Date)
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    experience_level = db.Column(db.String(50))  # Beginner, Intermediate, etc.
    distance_goal = db.Column(db.Float)  # Distance goal in km or miles
    preferences = db.Column(db.Text)  # JSON string or text for preferences
    mobile_no = db.Column(db.String(15))  # Include country code if necessary
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self) -> str:
        return f"User(user_sk={self.user_sk}, username={self.username}, email={self.email})"


class UserToken(db.Model):
    __tablename__ = 'user_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, db.ForeignKey(
        'users.user_sk'), nullable=False)
    # e.g., 'google', 'strava'
    provider = db.Column(db.String(50), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255))
    token_expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('tokens', lazy=True))

    def __repr__(self) -> str:
        return f"UserToken(id={self.id}, user_sk={self.user_sk}, provider={self.provider})"


class Activity(db.Model):
    __tablename__ = 'activities'

    activity_id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, db.ForeignKey(
        'users.user_sk'), nullable=False)
    strava_activity_id = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(255))
    distance = db.Column(db.Float)
    moving_time = db.Column(db.Integer)
    elapsed_time = db.Column(db.Integer)
    total_elevation_gain = db.Column(db.Float)
    type = db.Column(db.String(50))
    start_date = db.Column(db.DateTime)
    description = db.Column(db.Text)
    calories = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('activities', lazy=True))

    def __repr__(self) -> str:
        return f"Activity(activity_id={self.activity_id}, user_sk={self.user_sk}, name={self.name})"


class StravaMetric(db.Model):
    __tablename__ = 'strava_metrics'

    metric_id = db.Column(db.Integer, primary_key=True)
    user_sk = db.Column(db.Integer, db.ForeignKey(
        'users.user_sk'), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey(
        'activities.activity_id'), nullable=False)
    pace = db.Column(db.Float)
    heart_rate = db.Column(db.Float)
    cadence = db.Column(db.Float)
    power = db.Column(db.Float)

    user = db.relationship('User', backref=db.backref('metrics', lazy=True))
    activity = db.relationship(
        'Activity', backref=db.backref('metrics', lazy=True))

    def __repr__(self) -> str:
        return f"StravaMetric(metric_id={self.metric_id}, user_sk={self.user_sk}, activity_id={self.activity_id})"
