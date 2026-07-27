# Nix flake for oscar CLI (source build).
#
#   nix build
#   nix run
#   nix profile install .
#
{
  description = "oscar — multi-cloud native dredger agentic CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.stable.latest.default;
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "oscar";
          version = "0.1.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          buildAndTestSubdir = "crates/oscar-cli";
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];
          doCheck = false;
          meta = with pkgs.lib; {
            description = "Multi-cloud agentic CLI (AWS/GCP/Azure/K8s)";
            homepage = "https://github.com/JacksonJRay/oscar";
            license = licenses.asl20;
            mainProgram = "oscar";
          };
        };
        apps.default = flake-utils.lib.mkApp { drv = self.packages.${system}.default; };
        devShells.default = pkgs.mkShell {
          packages = [ rust pkgs.pkg-config pkgs.openssl pkgs.cargo-watch ];
        };
      });
}
