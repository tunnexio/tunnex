{
  description = "Verified Tunnex CLI packages";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d6524aaca2ff07876657ae2b323f24be4874944b";
  outputs = { self, nixpkgs }: {
    packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; };
          cli = pkgs.callPackage ./nix/package.nix {};
      in { tunnex-cli = cli; default = cli; });
  };
}
