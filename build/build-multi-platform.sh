#!/bin/bash

# Script to build multi-platform Docker images for kernel-delay

# Enable docker buildx
docker buildx create --name mybuilder --use --bootstrap 2>/dev/null || docker buildx use mybuilder

# Build for AMD64
echo "Building for AMD64..."
docker buildx build \
  --platform linux/amd64 \
  -t kernel-delay:latest-amd64 \
  -f build/Dockerfile \
  --load \
  .

# Build for ARM64
echo "Building for ARM64..."
docker buildx build \
  --platform linux/arm64 \
  -t kernel-delay:latest-arm64 \
  -f build/Dockerfile \
  --load \
  .

echo "Multi-platform Docker images built successfully!"
echo "Supported platforms: linux/amd64, linux/arm64"
echo "Images: kernel-delay:latest-amd64 and kernel-delay:latest-arm64"