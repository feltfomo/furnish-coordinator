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
        let
          faultInjection = import ./package.nix {
            inherit pkgs;
            suffix = "-fault-injection";
            features = [ "fault-injection" ];
          };

          # the crate only, so a flake.nix edit doesn't redo these
          crateSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./src
              ./tests
            ];
          };

          frozenSuites = pkgs.writeText "frozen-suites" ''
            fabf4b9da140655c60d55c564ff436bc  tests/characterization.rs
            aa87e6cecd892b86db64bc094f387986  tests/cli.rs
            1d57dd44d08b4fca6f878b01df5e9afa  tests/crash_recovery.rs
            9c69bcd104bad8e2dccb4b862ee129c7  tests/diagnostics.rs
            337e2a50592af569e8d17aca34e98c2c  tests/lifecycle.rs
          '';
        in
        {
          treefmt = import ./formatter.nix;

          # for building and CI inside this repo. furnish calls mkCoordinator
          # with its own pkgs rather than consuming this output.
          packages.default = import ./package.nix { inherit pkgs; };
          packages.fault-injection = faultInjection;

          # buildRustPackage runs cargo test in its check phase, so the crate's
          # unit tests and the five integration suites under tests/ are the check.
          checks.coordinator = config.packages.default;

          # the same suites again with the fault points compiled in
          checks.fault-injection = faultInjection;

          # fault points live behind the feature, so the shipped binary must
          # carry no trace of them and the feature build must.
          checks.fault-boundary = pkgs.runCommand "furnish-coordinator-fault-boundary" { } ''
            if grep -rq FURNISH_FAULT_POINT ${config.packages.default}/bin; then
              echo "fault points leaked into the default build" >&2
              exit 1
            fi
            grep -rq FURNISH_FAULT_POINT ${faultInjection}/bin
            touch $out
          '';

          # the suites are frozen by hash, so this only has to count the
          # suppressions in src.
          checks.crate-invariants = pkgs.runCommand "furnish-coordinator-crate-invariants" { } ''
            cd ${crateSource}
            md5sum -c ${frozenSuites}
            suppressions=$(grep -ro 'allow(clippy::too_many_arguments)' src | wc -l)
            if [ "$suppressions" -ne 2 ]; then
              echo "expected 2 clippy suppressions, found $suppressions" >&2
              exit 1
            fi
            touch $out
          '';

          checks.clippy = config.packages.default.overrideAttrs (old: {
            pname = "furnish-coordinator-clippy";
            nativeBuildInputs = old.nativeBuildInputs or [ ] ++ [ pkgs.clippy ];
            buildPhase = "cargo clippy --all-targets --all-features -- -D warnings";
            doCheck = false;
            installPhase = "touch $out";
          });

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
