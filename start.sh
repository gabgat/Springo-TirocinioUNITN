#!/bin/bash

# Variables - modify these as needed
FOLDER_NAME="${1:-scan_results}"          # First argument or default to "scan_results"
DOCKER_IMAGE_NAME="${2:-sprinpy:latest}"  # Second argument or default to "sprinpy:latest"

echo "Using folder: $FOLDER_NAME"
echo "Looking for Docker image: $DOCKER_IMAGE_NAME"

# Check if folder exists, create if it doesn't
if [ ! -d "$FOLDER_NAME" ]; then
    echo "Folder '$FOLDER_NAME' does not exist. Creating it..."
    mkdir -p "$FOLDER_NAME"
    echo "Folder '$FOLDER_NAME' created successfully."
else
    echo "Folder '$FOLDER_NAME' already exists."
fi

# Check if .env file exists in current directory
if [ ! -f ".env" ]; then
    echo "Env file not found"
    exit 1
fi

echo ".env file found in current directory."

# Check if Docker image exists
if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^$DOCKER_IMAGE_NAME$"; then
    echo "Docker image '$DOCKER_IMAGE_NAME' not found. Building sprinpy:latest..."
    docker build -t sprinpy:latest .
    if [ $? -ne 0 ]; then
        echo "Docker build failed. Exiting."
        exit 1
    fi
    echo "Docker image built successfully."
else
    echo "Docker image '$DOCKER_IMAGE_NAME' found."
fi

# Get user input for scan parameters
echo "Enter scan parameters:"

# Get IP address
read -p "Enter IP address to scan: " IP_ADDRESS
if [ -z "$IP_ADDRESS" ]; then
    echo "IP address is required. Exiting."
    exit 1
fi

# Get scan intensity (1-3, default 1)
read -p "Enter scan intensity (1-3) [default: 1]: " INTENSITY
INTENSITY=${INTENSITY:-1}

# Validate intensity value
if [[ ! "$INTENSITY" =~ ^[1-3]$ ]]; then
    echo "Invalid intensity value. Must be between 1 and 3. Using default value 1."
    INTENSITY=1
fi

# Get number of threads (default 40)
read -p "Enter number of threads [default: 40]: " THREADS
THREADS=${THREADS:-40}

# Validate threads value (should be a positive integer)
if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -eq 0 ]; then
    echo "Invalid threads value. Must be a positive integer. Using default value 40."
    THREADS=40
fi

# Get absolute path of the folder for Docker volume mounting
ABSOLUTE_PATH=$(realpath "$FOLDER_NAME")

# Run Docker container
echo "Starting Docker container..."
echo "Command: docker run -d -v $ABSOLUTE_PATH:/app/outputs --env-file .env $DOCKER_IMAGE_NAME $IP_ADDRESS -i $INTENSITY -t $THREADS"

CONTAINER_ID=$(docker run -d -v "$ABSOLUTE_PATH:/app/outputs" --env-file ".env" "$DOCKER_IMAGE_NAME" "$IP_ADDRESS" -i "$INTENSITY" -t "$THREADS")

if [ $? -eq 0 ]; then
    echo "Docker container started successfully with ID: $CONTAINER_ID"
    echo "You can check the logs with: docker logs $CONTAINER_ID"
    echo "Output files will be saved in: $ABSOLUTE_PATH"
else
    echo "Failed to start Docker container."
    exit 1
fi