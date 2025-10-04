# Use a slim Python base image to reduce size
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies (minimal for psycopg2-binary and others)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and install dependencies without cache to save space
COPY pyproject.toml .
RUN pip install --no-cache-dir -e . \
    && pip cache purge

# Copy the rest of the application code
COPY . .

# Expose port 5000
EXPOSE 5000

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers=2", "main:app"]