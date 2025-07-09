{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/*.tar.gz";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/*.tar.gz";
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    ...
  }: let


    rustVersion = "1.86.0";

    allSystems = [
      "aarch64-linux"
      "x86_64-linux"
    ];

    forEachSystem = f:
      nixpkgs.lib.genAttrs allSystems (system:
        f {
          inherit system;
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              rust-overlay.overlays.default
            ];
          };
        });
  in {
    devShells = forEachSystem ({
      pkgs,
      system,
    }: {
      default = pkgs.mkShell {

        shellHook = with pkgs; ''
          echo
          echo "🦾 QUASH Rust environment (rust: ${rustVersion})"
          echo


          echo ${rustc.name}
          echo ${cargo.name}
          echo
          echo ${cargo-watch.name}
          echo ${glibc.name}
          echo ${nushell.name}
          echo ${just.name}
          echo
          echo $(rustc --version)
          echo $(cargo --version)
          echo

          echo RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
        '';


        packages = with pkgs; [
          openssl
          pkg-config # Needed by rust to find libraries
          just
          nushell
          glibc
	  pre-commit
          (rust-bin.stable."${rustVersion}".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
          })
        ];
      };
    });
  };
}
