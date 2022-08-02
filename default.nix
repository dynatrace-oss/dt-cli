let
  nixpkgs = builtins.fetchGit {
    url = "https://github.com/nixos/nixpkgs/";
    ref = "refs/heads/nixos-unstable";
    rev = "f2537a505d45c31fe5d9c27ea9829b6f4c4e6ac5"; # 27-06-2022
    # obtain via `git ls-remote https://github.com/nixos/nixpkgs nixos-unstable`
  };
  pkgs = import nixpkgs { config = {}; };
  pythonCore = pkgs.python39;
  myPython = pythonCore.withPackages pythonPkgs;
  pythonPkgs = python-packages: with python-packages; [
      poetry
      python-lsp-server
    ];
  env = pkgs.buildEnv {
    name = "dtcli-dev-env";
    paths =
    with pkgs;
    [
      git
      gnumake
      myPython
      entr
      rnix-lsp
    ];
  };
in
{
  shell = pkgs.mkShell {
    buildInputs = [ env ];
  };
}
