from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_BRIDGE_PATH = Path(__file__).with_name("bridge_mcp_ghidra.py")
_BRIDGE_SPEC = spec_from_file_location("_ghidra_mcp_bridge_impl", _BRIDGE_PATH)

if _BRIDGE_SPEC is None or _BRIDGE_SPEC.loader is None:
    raise ImportError(f"Unable to load bridge module from {_BRIDGE_PATH}")

_BRIDGE_MODULE = module_from_spec(_BRIDGE_SPEC)
_BRIDGE_SPEC.loader.exec_module(_BRIDGE_MODULE)
main = _BRIDGE_MODULE.main

if __name__ == "__main__":
    main()
