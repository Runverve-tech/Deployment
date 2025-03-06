FROM python:3.12

# Set environment variables
ENV OAUTHLIB_INSECURE_TRANSPORT=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

# Set the correct working directory
WORKDIR /Runverve-cred-api

# Copy only requirements.txt first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files after installing dependencies
COPY . .

# Ensure venv is not copied (Docker ignores .gitignore by default)
RUN rm -rf venv

# Create a non-root user and switch to it for security
RUN useradd -m appuser
USER appuser

# Expose Flask port
EXPOSE 5000

# Run the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]