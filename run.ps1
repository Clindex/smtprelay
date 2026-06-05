pwsh -Command {
    $env:OTEL_SDK_DISABLED = $true;
    go run -v . `
        -config=".\smtprelay.ini" `
        -listen="127.0.0.1:2525" -hostname=localhost `
        -remote_host="email-smtp.us-east-1.amazonaws.com:587" `
        -remote_user="$(op read "op://Employee/AWS SES Dev Creds/username")" `
        -remote_pass="$(op read "op://Employee/AWS SES Dev Creds/password")"
}
