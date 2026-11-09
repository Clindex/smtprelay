pwsh -Command {
    $env:GOOS = "linux";
    $env:GOARCH = "amd64";
    go build -v
    go build ./cmd/hasher.go
}
