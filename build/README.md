# Multi-Platform Docker Build for kernel-delay

This directory contains the Dockerfile and build scripts for creating multi-platform Docker images for the kernel-delay application.

## Supported Platforms

- `linux/amd64` (x86_64)
- `linux/arm64` (aarch64)

## Prerequisites

1. Docker with buildx support (Docker Desktop or Docker Engine 19.03+)
2. Enabled buildx builder

## Building Multi-Platform Images

### Using the build script

```bash
# Make the script executable
chmod +x build/build-multi-platform.sh

# Run the build script
./build/build-multi-platform.sh
```

### Manual build commands

1. Create and use a buildx builder:
   ```bash
   docker buildx create --name mybuilder --use --bootstrap
   ```

2. Build for multiple platforms:
   ```bash
   docker buildx build \
     --platform linux/amd64,linux/arm64 \
     -t kernel-delay:latest \
     -f build/Dockerfile \
     .
   ```

3. To push to a registry, add `--push`:
   ```bash
   docker buildx build \
     --platform linux/amd64,linux/arm64 \
     -t your-registry/kernel-delay:latest \
     -f build/Dockerfile \
     --push \
     .
   ```

## Running the Container

Since kernel-delay requires eBPF capabilities and access to kernel data, it must be run with elevated privileges:

```bash
docker run --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  kernel-delay:latest --pid <PID> --duration <SECONDS>
```

## How It Works

The Dockerfile uses Docker's multi-stage build pattern:

1. **Builder Stage**: Uses a Rust image to compile the application for the target platform
2. **Runtime Stage**: Uses a minimal Alpine image with only the necessary runtime dependencies

The multi-platform support is achieved through Docker's buildx feature, which can build images for different architectures using QEMU emulation when needed.