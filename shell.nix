let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  packages = [
    (pkgs.python312.withPackages (python-pkgs: [
      python-pkgs.cryptography
      python-pkgs.tomli-w
      python-pkgs.dacite
      python-pkgs.black
    ]))
  ];

  shellHook = ''
    export AUTOCA_CONFIG="$PWD/config.toml"
    export AUTOCA_LOG="$PWD/latest.log"
  '';
  AUTOCA_LOGLEVEL = "INFO";
}
