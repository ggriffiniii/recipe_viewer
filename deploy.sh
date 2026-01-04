#!/bin/bash
set -e

echo "1. Building x86 Docker image..."
docker build -f Dockerfile.cross --platform linux/amd64 -t recipe_viewer-x86 .

echo "2. Saving Docker image to tar file..."
docker save -o /tmp/recipe_viewer-x86.tar recipe_viewer-x86:latest

echo "3. Transferring image to syn.chiffins.com..."
scp /tmp/recipe_viewer-x86.tar syn.chiffins.com:/tmp/

echo "4. Deploying on syn.chiffins.com..."
ssh syn.chiffins.com "docker load -i /tmp/recipe_viewer-x86.tar && sudo systemctl restart docker.bitwarden.service"

echo "Deployment complete!"
