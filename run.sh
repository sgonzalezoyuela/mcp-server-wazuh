#!/bin/bash

if [ ! -f .env ]; then
    echo "No .env file found. Creating from .env.example..."
    cp .env.example .env
    echo "Please edit .env file with your configuration."
    exit 1
fi

cargo run
