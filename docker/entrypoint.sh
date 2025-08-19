#!/bin/sh

# If first argument is not executable or no arguments provided, run altinity-mcp
if [ -z "$1" ] || [ ! -x "$(which "$1" 2>/dev/null)" ]; then
    exec /bin/altinity-mcp "$@"
else
    # Otherwise execute the specified command
    exec "$@"
fi
