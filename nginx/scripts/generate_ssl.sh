#!/bin/bash
set -e

SSL_DIR="../ssl"
DOMAIN="merkur"

mkdir -p "$SSL_DIR"

echo "Generating self-signed certificate for $DOMAIN..."

openssl req -x509 \
  -nodes \
  -days 365 \
  -newkey rsa:2048 \
  -keyout "$SSL_DIR/key.pem" \
  -out "$SSL_DIR/cert.pem" \
  -subj "/C=DE/ST=Hamburg/L=Hamburg/O=HAW Hamburg/OU=Department Informatik/CN=$DOMAIN"
echo "Self-signed certificate created at $SSL_DIR"

