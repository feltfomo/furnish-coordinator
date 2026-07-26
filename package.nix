# one definition of the coordinator build, for every caller. a build flag can no
# longer be added at one call site and missed at the others, which is what this
# file removes. it does not make the outputs identical on its own. the checks and
# the flake package hand it the same perSystem pkgs and so land on one
# derivation, while the binary the unit runs comes from the nixos module's pkgs,
# which is that host's nixpkgs after its overlays. identical pkgs is what makes
# those the same output.
{
  pkgs,
  suffix ? "",
  features ? [ ],
}:
pkgs.rustPlatform.buildRustPackage {
  pname = "furnish-coordinator${suffix}";
  version = "0.1.0";
  src = ./coordinator;
  cargoLock.lockFile = ./coordinator/Cargo.lock;
  # set even when it is empty, because an absent buildFeatures and an empty one
  # are the same cargo invocation but not the same derivation. two callers
  # disagreeing about which form to use is what built the shipped coordinator
  # twice, to two store paths, from identical source and identical flags.
  buildFeatures = features;
}
