#!/bin/bash
set -e

# Create SSL directory if it doesn't exist
mkdir -p ssl

# Check if certificates already exist
if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
    echo "Generating self-signed SSL certificates for auth service..."
    
    # Generate self-signed certificate
    openssl req -x509 \
        -nodes \
        -days 365 \
        -newkey rsa:2048 \
        -keyout ssl/key.pem \
        -out ssl/cert.pem \
        -subj "/C=DE/ST=Hamburg/L=Hamburg/O=HAW Hamburg/OU=Department Informatik/CN=auth.merkur"
    
    echo "SSL certificates generated successfully!"
else
    echo "SSL certificates already exist, skipping generation."
fi 