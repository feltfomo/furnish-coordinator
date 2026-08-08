{
  description = "the furnish coordinator, reconciling declared files against a durable ledger";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.treefmt-nix.flakeModule ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      # a function of pkgs, not a built package. the nixos module that runs the
      # binary builds it with the host's pkgs, after that host's overlays;
      # handing out a package built from this flake's own nixpkgs is what puts
      # the unit and the flake package on two store paths from identical source.
      flake.lib.mkCoordinator = import ./package.nix;

      perSystem =
        { config, pkgs, ... }:
        {
          treefmt = import ./formatter.nix;

          # for building and CI inside this repo. furnish calls mkCoordinator
          # with its own pkgs rather than consuming this output.
          packages.default = import ./package.nix { inherit pkgs; };

          # buildRustPackage runs cargo test in its check phase, so the crate's
          # unit tests and the five integration suites under tests/ are the check.
          checks.coordinator = config.packages.default;

          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
            ];
          };
        };
    };
}
