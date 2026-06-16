#!/bin/bash

set -e

echo "Generating CA certificate..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key ca.key -out ca.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test CA/OU=Test/CN=Test CA" 2>/dev/null

echo "Generating default certificate (localhost)..."
openssl genrsa -out default.key 2048 2>/dev/null
openssl req -new -key default.key -out default.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Default Server/OU=Default/CN=localhost" 2>/dev/null
openssl x509 -req -days 365 -in default.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out default.pem 2>/dev/null

echo "Generating SNI certificate (sni.com)..."
openssl genrsa -out sni.key 2048 2>/dev/null
openssl req -new -key sni.key -out sni.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=SNI Server/OU=SNI/CN=sni.com" 2>/dev/null
openssl x509 -req -days 365 -in sni.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out sni.pem 2>/dev/null

echo "Generating NOSNI certificate (nosni.com)..."
openssl genrsa -out nosni.key 2048 2>/dev/null
openssl req -new -key nosni.key -out nosni.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=NOSNI Server/OU=NOSNI/CN=nosni.com" 2>/dev/null
openssl x509 -req -days 365 -in nosni.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out nosni.pem 2>/dev/null

echo "Cleaning up CSR files..."
rm -f *.csr

echo "Certificates generated successfully!"
echo "  - Default: default.pem (CN=localhost)"
echo "  - SNI: sni.pem (CN=sni.com)"
echo "  - NOSNI: nosni.pem (CN=nosni.com)"
echo "  - CA: ca.pem"
