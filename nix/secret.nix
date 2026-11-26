{
  lib,
  stdenv,
  swift,
  swiftpm,
}:
stdenv.mkDerivation {
  pname = "secret";
  version = "2.7.0";

  # Only the Swift package: `.build` and `.swiftpm` are local artefacts and
  # would otherwise be copied into the store on a dirty tree.
  src = lib.cleanSourceWith {
    src = ../secret;
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
    install -Dm755 "$NIX_BUILD_TOP/.build/release/secret" "$out/bin/secret"
    install -Dm644 ${../secret/secret.1} "$out/share/man/man1/secret.1"
    runHook postInstall
  '';

  # nixpkgs' swift-on-darwin links a few stdlib dylibs from its own corelibs
  # store runtime, which dies with SIGKILL at dyld load when mixed with the
  # system runtime. The system runtime is ABI-compatible, so repoint them.
  postFixup = lib.optionalString stdenv.isDarwin ''
    for dylib in $(/usr/bin/otool -L "$out/bin/secret" | awk '/\/nix\/store\/.*\/lib\/swift\// { print $1 }'); do
      /usr/bin/install_name_tool -change "$dylib" "/usr/lib/swift/$(basename "$dylib")" "$out/bin/secret"
    done
  '';

  meta = {
    description = "Value-minimizing secret manager for configured aliases";
    homepage = "https://github.com/astahmer/secret-cli";
    license = lib.licenses.mit;
    mainProgram = "secret";
    platforms = lib.platforms.darwin;
  };
}
