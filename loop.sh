#!/bin/bash

# Define the command you want to run
COMMAND="/Users/bui/Tools/fromA2Z/fromA2Z auth -refresh"

while true; do
    # Execute the command in the background so the sleep interval stays accurate
    $COMMAND  
    
    # Wait for 30 minutes before looping again
    sleep 1800
done
