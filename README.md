# Crescent DKIM
Crescent DKIM system is designed for verifying on-chain ownership by DKIM with privacy.

# Setup
- `make init` to install dependencies.
- `make prove` to compile the circuit, run tests and generate witnesses. If there exist compiled circuit files in `build_circuits` folder, it will skip compilation.
- `make clean` to remove all files in `build_circuits`.

**Warning**
Circom 2.0.6 is required for this project. If you’re using a different version, it could lead to errors in test JS files as current snarkjs and higher circom compiler are incompatible in some functions.