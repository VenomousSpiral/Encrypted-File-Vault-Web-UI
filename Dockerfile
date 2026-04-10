FROM python:3.12-slim

WORKDIR /app

# Install ffmpeg for HLS transcoding
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory
RUN mkdir -p /app/data

EXPOSE 5000

CMD ["python", "run.py"]
