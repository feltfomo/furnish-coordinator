{
  projectRootFile = "flake.nix";

  programs.nixfmt.enable = true;
  programs.statix.enable = true;

  # treefmt-nix defaults rustfmt to the 2018 edition, and the crate is on 2024.
  programs.rustfmt.enable = true;
  programs.rustfmt.edition = "2024";
}
