{
  description = "Convert OCI/Docker images into self-contained ELF executables";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      packages.x86_64-linux.default = pkgs.stdenv.mkDerivation {
        pname = "oci2bin";
        version = "0.1.0";
        src = ./.;

        nativeBuildInputs = [ pkgs.musl pkgs.makeWrapper ];

        buildPhase = ''
          musl-gcc -static -O2 -s -Wall -Wextra -o loader src/loader.c
        '';

        installPhase = ''
          mkdir -p $out/bin $out/share/oci2bin/scripts $out/share/oci2bin/build $out/share/oci2bin/src

          install -m 755 loader                        $out/share/oci2bin/build/loader
          install -m 644 src/loader.c                  $out/share/oci2bin/src/loader.c
          install -m 644 scripts/build_polyglot.py     $out/share/oci2bin/scripts/build_polyglot.py

          install -m 755 oci2bin $out/share/oci2bin/oci2bin-inner
          # Loader is pre-compiled; remove the musl-gcc runtime check
          sed -i '/need musl-gcc/d' $out/share/oci2bin/oci2bin-inner
          # Hardcode OCI2BIN_HOME to the Nix store path
          sed -i "s|OCI2BIN_HOME:-\$SCRIPT_DIR|OCI2BIN_HOME:-$out/share/oci2bin|" \
              $out/share/oci2bin/oci2bin-inner

          makeWrapper $out/share/oci2bin/oci2bin-inner $out/bin/oci2bin \
            --prefix PATH : ${pkgs.python3}/bin
        '';

        meta = with pkgs.lib; {
          description = "Convert OCI/Docker images into self-contained ELF executables";
          license = licenses.mit;
          platforms = [ "x86_64-linux" ];
          mainProgram = "oci2bin";
        };
      };

      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [ pkgs.musl pkgs.python3 pkgs.docker pkgs.astyle ];
      };
    };
}
