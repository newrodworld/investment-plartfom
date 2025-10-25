#!/bin/bash
while true; do
    echo "Starting public tunnel..."
    ssh -o ServerAliveInterval=60 -R 80:localhost:5000 serveo.net
    echo "Tunnel disconnected. Reconnecting in 10 seconds..."
    sleep 10
done
