{
  description = "Development shell for ghidra-mcp";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/c71235aa6275d681dae82a690297763124501f01";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          jdk = pkgs.jdk21_headless;
          python = pkgs.python312;
        in
        {
          default = pkgs.mkShell {
            packages = [
              jdk
              python
              pkgs.uv
            ];

            JAVA_HOME = jdk;
            UV_PYTHON = "${python}/bin/python3";

            shellHook = ''
              echo "ghidra-mcp dev shell"
              echo "Set GHIDRA_INSTALL_DIR to the pinned Ghidra 12.1.2 installation."
              echo "Use ./ghidra_extension/build.sh to build the extension zip."
            '';
          };
        }
      );
    };
}
