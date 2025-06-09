FROM python:3.11-slim

WORKDIR /app

# Install OpenSSL for certificate generation
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/

# Upgrade pip
RUN python -m pip install --upgrade pip

RUN pip install -r requirements.txt

COPY . /app

# Generate SSL certificates if they don't exist
RUN chmod +x install.sh && ./install.sh

EXPOSE 5000

CMD ["python", "app.py"]

