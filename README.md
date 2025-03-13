# Flask API Template With SQLAlchemy

## Installation

1. Clone the repository
2. Install the dependencies, recommended to use a virtual environment

```
pip install -r requirements.txt
```

3. Either use the deafult PostgreSQL URI in `.env` or use your custom PostgreSQL URI

```
DATABASE_URI=<your-database-uri>
```

4. Run the application

```
python app.py
```

## Creating An Endpoint

Refer to the `app.py` file to see how to endpoints are created /users and how to use the SQLAlchemy ORM to interact with the database.
