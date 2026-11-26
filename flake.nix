{
  description = "secret — value-minimizing secret manager for configured aliases (CLI + SecretBar)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.secret;
        secret = pkgs.callPackage ./nix/secret.nix { };
        secretbar = pkgs.callPackage ./nix/secretbar.nix { };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.secret}/bin/secret";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.swift
            pkgs.swiftpm
            pkgs.python3
          ];
        };
      });
    };
}
