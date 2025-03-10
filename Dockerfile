FROM python:3.12-alpine
WORKDIR /userpreferences
COPY . /userpreferences
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python3","user_preferences.py"]

# # Common Dockerfile
# FROM python:3.12-alpine
# WORKDIR /apps
# COPY . /apps
# RUN pip install -r requirements.txt
# # Use a build argument to specify the Flask app
# ARG FLASK_APP=app.py
# ENV FLASK_APP=$FLASK_APP
# EXPOSE 5000
# CMD python3 $FLASK_APP
