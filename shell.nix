with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "hotboot";
  buildInputs = [
    rustc
    cargo
    pkgconfig
    openssl
  ];
}
