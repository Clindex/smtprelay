$tenantId = "feaae8a4-e991-4da8-b4e2-cc9d19b6f2fe"
$clientId = "9e8cadb0-281d-4531-b27c-9bde7c4b8a33"
$clientSecret = "$(op read "op://Employee/MLJ-Dev Entra SMTP Creds/credential")"

$response = Invoke-RestMethod `
    -Method Post `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Body @{
        client_id = $clientId
        client_secret = $clientSecret
        scope = "https://outlook.office365.com/.default"
        grant_type = "client_credentials"
    }

$response | fl -Property *
$accessToken = $response.access_token
Write-Host "Access Token: $accessToken"
