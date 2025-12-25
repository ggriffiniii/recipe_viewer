---
description: Build the x86 Docker image and save it to a tar file
---
// turbo
1. Build the x86 image: `docker build -f Dockerfile.cross --platform linux/amd64 -t recipe_viewer-x86 .`
// turbo
2. Save the image to a tar file: `docker save -o recipe_viewer-x86.tar recipe_viewer-x86:latest`
