"""Exercise the real network discovery method with small HA stand-ins."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest


source = Path(__file__).parents[1] / "custom_components/uniled/config_flow.py"
tree = ast.parse(source.read_text())
flow_class = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "UniledConfigFlowHandler")
method = next(n for n in flow_class.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_async_network_discovery")
module = ast.Module(body=[method], type_ignores=[])


class AbortFlow(Exception):
    pass


class Registry:
    def __init__(self):
        self.updated = []
        self.reloaded = []

    def async_update_entry(self, entry, **kwargs):
        self.updated.append((entry, kwargs))

    def async_schedule_reload(self, entry_id):
        self.reloaded.append(entry_id)


from test_mac import mac


def populate(_old, updates, device):
    updates.update(transport=device["transport"], host=device["ip_address"], model=device["model_name"])


scope = {
    "__builtins__": __builtins__, "Any": object, "FlowResult": object,
    "ATTR_UL_MAC_ADDRESS": "mac_address", "ATTR_UL_IP_ADDRESS": "ip_address",
    "ATTR_UL_MODEL_CODE": "model_code", "ATTR_UL_MODEL_NAME": "model_name",
    "ATTR_UL_TRANSPORT": "transport", "CONF_TRANSPORT": "transport", "CONF_MODEL": "model",
    "UNILED_TRANSPORT_NET": "net", "UNILED_TRANSPORT_BLE": "ble",
    "dr": SimpleNamespace(format_mac=lambda value: value.lower()),
    "same_mac": mac.same_mac, "AbortFlow": AbortFlow,
    "flow": SimpleNamespace(SOURCE_IGNORE="ignore", ConfigEntryState=SimpleNamespace(SETUP_IN_PROGRESS="progress", NOT_LOADED="not_loaded", SETUP_RETRY="retry")),
    "async_populate_data_from_discovery": populate,
}
exec(compile(ast.fix_missing_locations(module), str(source), "exec", dont_inherit=True), scope)


class Flow:
    _async_network_discovery = scope["_async_network_discovery"]

    def __init__(self, entries):
        self._discovered_device = {"mac_address": "e8:06:90:69:75:ce", "ip_address": "192.0.2.1", "model_code": 78, "model_name": "SP530E", "transport": "net"}
        self.entries = entries
        self.hass = SimpleNamespace(config_entries=Registry())

    async def async_set_unique_id(self, value):
        self.unique_id = value

    def _async_current_entries(self, include_ignore=False):
        return self.entries


def entry(transport, unique_id="E8:06:90:69:75:CE", disabled_by=None):
    return SimpleNamespace(unique_id=unique_id, data={"transport": transport, "model": "SP530E"}, source="user", entry_id="stable", disabled_by=disabled_by)


class NetworkDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_ble_entry_is_upgraded_without_changing_id(self):
        existing = entry("ble")
        handler = Flow([existing])
        with self.assertRaisesRegex(AbortFlow, "already_configured"):
            await handler._async_network_discovery()
        self.assertEqual(handler.hass.config_entries.updated[0][1]["data"]["transport"], "net")
        self.assertEqual(handler.hass.config_entries.reloaded, ["stable"])
        self.assertEqual(existing.unique_id, "E8:06:90:69:75:CE")

    async def test_disabled_ble_entry_is_not_upgraded(self):
        handler = Flow([entry("ble", disabled_by="user")])
        with self.assertRaisesRegex(AbortFlow, "already_configured"):
            await handler._async_network_discovery()
        self.assertEqual(handler.hass.config_entries.updated, [])
