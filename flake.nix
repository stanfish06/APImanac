{
  description = "APImanac: a reviewed catalog of public APIs an agent can search and call";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      script = pkgs: name: text: pkgs.writeShellScriptBin name text;
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.bun
            pkgs.git
            (script pkgs "format" "bun run biome format --write .")
            (script pkgs "lint" "bun run biome lint .")
            (script pkgs "typecheck" "bun run tsc --noEmit")
            (script pkgs "test" "bun test")
            (script pkgs "build" "bun run src/cli.ts build")
            (script pkgs "compile" "bun build --compile --outfile dist/apimanac src/cli.ts")
          ];
        };
      });
    };
}
