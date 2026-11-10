from pathlib import Path

def capabilities() -> list[dict]:
    adapters = sorted(p.name for p in Path("/sys/class/bluetooth").glob("hci*"))
    result = []
    if not adapters:
        result.append({"kind": "local_ble_adapter", "device": None, "available": False,
                       "frequency_range_hz": None, "sample_rate_limits": None,
                       "operations": [], "required_permissions": ["BlueZ access"],
                       "driver_dependencies": ["BlueZ"], "detail": "no adapter found"})
    for adapter in adapters:
        result.append({"kind": "local_ble_adapter", "device": adapter, "available": False,
                       "frequency_range_hz": [2400000000, 2483500000], "sample_rate_limits": None,
                       "operations": [], "required_permissions": ["BlueZ access"],
                       "driver_dependencies": ["BlueZ"], "detail": "sysfs presence only; no live integration"})
    for kind in ("dedicated_ble_sniffer", "receive_only_sdr"):
        result.append({"kind": kind, "device": None, "available": False,
                       "frequency_range_hz": None, "sample_rate_limits": None,
                       "operations": [], "required_permissions": [],
                       "driver_dependencies": [], "detail": "not integrated"})
    result.append({"kind": "offline_capture_import", "device": "bleforensics supported files",
                   "available": True, "frequency_range_hz": None, "sample_rate_limits": None,
                   "operations": ["import", "analyze"], "required_permissions": ["file read"],
                   "driver_dependencies": ["Python 3.12"], "detail": "offline analysis"})
    return result
