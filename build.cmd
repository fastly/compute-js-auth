@echo off
if exist .env (
    for /f "tokens=1* delims==" %%A in (.env) do (
        set "%%A=%%B"
    )
) else (
    echo .env file not found
)
js-compute-runtime bin/index.js bin/main.wasm
