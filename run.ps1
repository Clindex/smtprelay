pwsh -Command {
    $env:OTEL_SDK_DISABLED = $true;
    go run -v . -listen="127.0.0.1:2525" -hostname=localhost
}
