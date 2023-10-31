#!/bin/bash
if [ -f .env ]; then
    export $(xargs < .env) 2>/dev/null
else
    echo ".env file not found"
fi
js-compute-runtime bin/index.js bin/main.wasm