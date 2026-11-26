{
  lib,
  stdenv,
  swift,
  swiftpm,
}:
stdenv.mkDerivation {
  pname = "secretbar";
  version = "0.3.1";

  src = lib.cleanSourceWith {
    src = ../secretbar;
    filter =
      path: _type: !(builtins.elem (baseNameOf (toString path)) [ ".build" ".swiftpm" ]);
  };

  nativeBuildInputs = [
    swift
    swiftpm
  ];

  buildPhase = ''
    runHook preBuild
    swift build -c release --scratch-path "$NIX_BUILD_TOP/.build"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    app="$out/Applications/SecretBar.app"
    mkdir -p "$app/Contents/MacOS" "$out/bin"
    install -m755 "$NIX_BUILD_TOP/.build/release/secretbar" "$app/Contents/MacOS/secretbar"
    install -m644 "$src/Info.plist" "$app/Contents/Info.plist"
    cat > "$out/bin/secretbar" <<EOF
    #!/bin/sh
    exec /usr/bin/open "$app"
    EOF
    chmod +x "$out/bin/secretbar"
    runHook postInstall
  '';

  postFixup = lib.optionalString stdenv.isDarwin ''
    for binary in "$out/Applications/SecretBar.app/Contents/MacOS/secretbar"; do
      for dylib in $(/usr/bin/otool -L "$binary" | awk '/\/nix\/store\/.*\/lib\/swift\// { print $1 }'); do
        /usr/bin/install_name_tool -change "$dylib" "/usr/lib/swift/$(basename "$dylib")" "$binary"
      done
    done
  '';

  meta = {
    description = "Menu bar companion for the secret CLI";
    homepage = "https://github.com/astahmer/secret-cli";
    license = lib.licenses.mit;
    mainProgram = "secretbar";
    platforms = lib.platforms.darwin;
  };
}
