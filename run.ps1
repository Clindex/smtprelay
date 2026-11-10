pwsh -Command {
    $env:OTEL_SDK_DISABLED = $true;
    $env:OP_SERVICE_ACCOUNT_TOKEN = "$(op read "op://OIT/7zv3y52op3n2us34bffrgmglba/credential")"
    go run -v . -config="./smtprelay.ini" -listen="127.0.0.1:2525" -hostname=localhost
}
