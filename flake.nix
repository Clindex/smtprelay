{
    description = "smtprelay development environment";

    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    };

    outputs = { self, nixpkgs }:
    let
        supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin"
        "aarch64-darwin" ];
        forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
        devShells = forAllSystems (system:
        let
            pkgs = nixpkgs.legacyPackages.${system};

            golangci-lint = pkgs.golangci-lint.overrideAttrs (finalAttrs: prevAttrs: {
                version = "2.15.0";

                src = pkgs.fetchFromGitHub {
                    owner = "golangci";
                    repo = "golangci-lint";
                    tag = "v${finalAttrs.version}";
                    hash = "sha256-m9PoJHescRuT9DiKsb6LL+lQlc7RKAWDiRyf8pNMffA=";
                };

                vendorHash = "sha256-gWbhZc/BJwuiwyTMaR1ShEBI1lo0bGLCXsdj5n91baw=";
            });
        in
        {
            default = pkgs.mkShellNoCC {
                packages = with pkgs; [
                    go
                    gcc
                    golangci-lint
                ];
            };
        });
    };
}

