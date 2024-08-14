#!/bin/bash

# Start backend service
cd /root/Taint/backend || { echo "Failed to change directory to /root/Taint/backend"; exit 1; }
nohup npm start > backend.log 2>&1 &

# Start frontend service
cd /root/Taint/frontend/frontend || { echo "Failed to change directory to /root/Taint/frontend/frontend"; exit 1; }
nohup npm start > frontend.log 2>&1 &

echo "Backend and frontend services have been started."
