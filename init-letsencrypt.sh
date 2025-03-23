#!/bin/bash

# This script sets up Let's Encrypt certificates for your domain
# Adapted from https://github.com/wmnnd/nginx-certbot

if ! [ -x "$(command -v docker compose)" ]; then
  echo 'Error: docker compose is not installed.' >&2
  exit 1
fi

# Set default values
domains=(example.com www.example.com)
email="webmaster@example.com"
rsa_key_size=4096
staging=0 # Set to 1 if you're testing to avoid hitting request limits

# Make sure directories exist
mkdir -p ./certbot/conf/live/${domains[0]}
mkdir -p ./certbot/www
mkdir -p ./nginx/conf.d

# Replace domain name in the Nginx config file
sed -i.bak "s/example.com/${domains[0]}/g" ./nginx/conf.d/default.conf

# Create dummy certificates for the initial Nginx start
echo "Creating dummy certificate for ${domains[0]}..."
openssl req -x509 -nodes -newkey rsa:$rsa_key_size -days 1 \
  -keyout ./certbot/conf/live/${domains[0]}/privkey.pem \
  -out ./certbot/conf/live/${domains[0]}/fullchain.pem \
  -subj "/CN=${domains[0]}"
echo "Done creating dummy certificate."

# Create .htpasswd file for restricted areas
echo "Creating .htpasswd file for restricted access..."
docker run --rm httpd:alpine htpasswd -bn admin secure_password > ./nginx/.htpasswd
echo "Done creating .htpasswd file."

# Start Nginx
echo "Starting Nginx..."
docker compose up --force-recreate -d nginx
echo "Waiting for Nginx to start..."
sleep 5

# Delete dummy certificates to avoid conflicts with the real ones
echo "Deleting dummy certificates..."
rm -rf ./certbot/conf/live/${domains[0]}
echo "Done deleting dummy certificates."

# Request real certificates
echo "Requesting Let's Encrypt certificates..."

case "$staging" in
  0) staging_arg="--force-renewal" ;;
  1) staging_arg="--staging --force-renewal" ;;
esac

domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

docker compose run --rm certbot certonly --webroot -w /var/www/certbot \
  $staging_arg \
  $domain_args \
  --email $email \
  --rsa-key-size $rsa_key_size \
  --agree-tos \
  --no-eff-email

# Restart Nginx
echo "Restarting Nginx..."
docker compose restart nginx

echo "Done! Let's Encrypt certificates have been obtained successfully."