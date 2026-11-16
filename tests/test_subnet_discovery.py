"""Cross-subnet discovery: CIDR limits, the unicast sweep and host updates by MAC."""

import ast
import asyncio
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest

ROOT = Path(__file__).parents[1] / "custom_components/uniled"
# Import the HA-free library without running the integration's __init__.
package = ModuleType("uniled")
package.__path__ = [str(ROOT)]
sys.modules.setdefault("uniled", package)

from uniled.lib.discovery import CONF_TO_DISCOVERY  # noqa: E402
from uniled.lib.mac import same_mac  # noqa: E402
from uniled.lib.net import scanner  # noqa: E402

# Captured from an SP530E ("MB Curtain") answering a unicast probe.
REPLY = bytes.fromhex(
    "53704e65740000210000000000010000144e00e806906909ee0b4d42204375727461696e0000"
)


class CidrTests(unittest.TestCase):
    def test_networks_up_to_a_slash_22_are_accepted(self):
        networks = scanner.parse_discovery_networks(["10.10.30.0/24", " 10.10.28.0/22"])
        self.assertEqual([str(n) for n in networks], ["10.10.30.0/24", "10.10.28.0/22"])

    def test_host_bits_and_single_hosts_are_accepted(self):
        networks = scanner.parse_discovery_networks(["10.10.30.7/24", "10.10.30.126"])
        self.assertEqual(
            [str(n) for n in networks], ["10.10.30.0/24", "10.10.30.126/32"]
        )

    def test_oversized_and_invalid_networks_are_rejected(self):
        for value in (
            "10.10.0.0/21",
            "10.0.0.0/8",
            "10.10.30.0/33",
            "not-a-cidr",
            "fe80::/120",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.parse_discovery_networks([value])


class Sock:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, message, destination):
        self.sent.append((message, destination))

    def close(self):
        self.closed = True


class SweepTests(unittest.IsolatedAsyncioTestCase):
    async def test_probes_every_host_and_parses_replies(self):
        sock = Sock()
        replies = [(REPLY, ("10.10.30.1", 6454))]

        async def recvfrom(_sock, _size):
            if replies:
                return replies.pop()
            await asyncio.Event().wait()

        asyncio.get_running_loop().sock_recvfrom = recvfrom
        sweep = scanner.UniledNetScanner()
        sweep._create_socket = lambda: sock
        original_model = scanner.discovery_model
        scanner.discovery_model = lambda _discovery: None
        try:
            found = await sweep.async_sweep(
                scanner.parse_discovery_networks(["10.10.30.0/30"]), timeout=0.02
            )
        finally:
            scanner.discovery_model = original_model

        probe = (scanner.UniledNetScanner.SPNET_DISCOVERY_MESSAGE,)
        self.assertEqual(
            sock.sent,
            [
                (*probe, ("10.10.30.1", 6454)),
                (*probe, ("10.10.30.2", 6454)),
                # Second round re-probes only the host that stayed silent.
                (*probe, ("10.10.30.2", 6454)),
            ],
        )
        self.assertTrue(sock.closed)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["ip_address"], "10.10.30.1")
        self.assertEqual(found[0]["mac_address"], "E8:06:90:69:09:EE")
        self.assertEqual(found[0]["local_name"], "MB Curtain")
        self.assertEqual(found[0]["model_code"], 0x4E)

    async def test_cancelling_the_sweep_propagates_and_closes_socket(self):
        sock = Sock()

        async def recvfrom(_sock, _size):
            await asyncio.Event().wait()

        asyncio.get_running_loop().sock_recvfrom = recvfrom
        sweep = scanner.UniledNetScanner()
        sweep._create_socket = lambda: sock
        task = asyncio.ensure_future(
            sweep.async_sweep(scanner.parse_discovery_networks(["10.10.30.1/32"]), 10)
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(sock.closed)


def functions(path, names):
    tree = ast.parse(path.read_text())
    found = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    ]
    for node in found:
        node.decorator_list = []
    return ast.Module(body=found, type_ignores=[])


class AbortFlow(Exception):
    pass


class Registry:
    def __init__(self):
        self.reloaded = []

    def async_update_entry(self, entry, **kwargs):
        for key, value in kwargs.items():
            setattr(entry, key, value)
        return True

    def async_schedule_reload(self, entry_id):
        self.reloaded.append(entry_id)


State = SimpleNamespace(
    LOADED="loaded",
    SETUP_IN_PROGRESS="progress",
    NOT_LOADED="not_loaded",
    SETUP_RETRY="retry",
)
scope = {
    "__builtins__": __builtins__,
    "Any": object,
    "FlowResult": object,
    "Mapping": dict,
    "ATTR_UL_MAC_ADDRESS": "mac_address",
    "ATTR_UL_IP_ADDRESS": "ip_address",
    "ATTR_UL_LOCAL_NAME": "local_name",
    "ATTR_UL_MODEL_CODE": "model_code",
    "ATTR_UL_MODEL_NAME": "model_name",
    "ATTR_UL_TRANSPORT": "transport",
    "CONF_TRANSPORT": "transport",
    "CONF_MODEL": "model",
    "CONF_TO_DISCOVERY": CONF_TO_DISCOVERY,
    "UNILED_TRANSPORT_NET": "net",
    "UNILED_TRANSPORT_BLE": "ble",
    "_LOGGER": SimpleNamespace(debug=lambda *_: None),
    "dr": SimpleNamespace(format_mac=lambda value: value.lower()),
    "UniledDevice": SimpleNamespace(human_readable_name=lambda _self, name, mac: name),
    "same_mac": same_mac,
    "DOMAIN": "uniled",
    "UNILED_DISCOVERY": "uniled_discovery",
    "CONF_ADDRESS": "address",
    "CONF_RETRY_COUNT": "retry_count",
    "CONF_UPDATE_INTERVAL": "update_interval",
    "DEFAULT_RETRY_COUNT": 3,
    "DEFAULT_UPDATE_INTERVAL": 30,
    "AbortFlow": AbortFlow,
    "ConfigEntryState": State,
    "flow": SimpleNamespace(SOURCE_IGNORE="ignore", ConfigEntryState=State),
    "async_dispatcher_send": lambda *_: None,
}
for path, names in (
    (
        ROOT / "discovery.py",
        {
            "async_update_entry_from_discovery",
            "async_populate_data_from_discovery",
            "async_name_from_discovery",
            "async_cached_sp530e",
        },
    ),
    (
        ROOT / "config_flow.py",
        {
            "_async_network_discovery",
            "_async_bluetooth_create_entry",
            "_async_network_create_entry",
        },
    ),
):
    exec(
        compile(ast.fix_missing_locations(functions(path, names)), str(path), "exec"),
        scope,
    )


KIDS_BATH = {
    "transport": "net",
    "source": "UDP",
    "mac_address": "F0:F5:BD:C4:A2:16",
    "ip_address": "10.10.30.174",
    "local_name": "Kids Bath",
    "model_code": 78,
    "model_name": "SP530E",
}


class Flow:
    _async_network_discovery = scope["_async_network_discovery"]
    _async_bluetooth_create_entry = scope["_async_bluetooth_create_entry"]
    _async_network_create_entry = scope["_async_network_create_entry"]

    def async_create_entry(self, **kwargs):
        return kwargs

    def __init__(self, entries, device):
        self._discovered_device = device
        self.entries = entries
        self.hass = SimpleNamespace(config_entries=Registry())

    async def async_set_unique_id(self, value):
        self.unique_id = value

    def _async_current_entries(self, include_ignore=False):
        return self.entries


class HostUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def test_mac_match_with_new_ip_updates_host_and_reloads(self):
        existing = SimpleNamespace(
            unique_id="e8:06:90:69:09:ee",
            entry_id="stable",
            source="user",
            disabled_by=None,
            title="MB Curtain",
            state=State.LOADED,
            data={
                "transport": "net",
                "host": "10.10.30.99",
                "name": "MB Curtain",
                "model": "SP530E",
            },
        )
        device = {
            "transport": "net",
            "source": "UDP",
            "mac_address": "E8:06:90:69:09:EE",
            "ip_address": "10.10.30.126",
            "local_name": "MB Curtain",
            "model_code": 78,
            "model_name": "SP530E",
        }
        handler = Flow([existing], device)
        with self.assertRaisesRegex(AbortFlow, "already_configured"):
            await handler._async_network_discovery()
        self.assertEqual(existing.data["host"], "10.10.30.126")
        self.assertEqual(existing.unique_id, "e8:06:90:69:09:ee")
        self.assertEqual(handler.hass.config_entries.reloaded, ["stable"])

    async def test_ble_only_sp530e_converts_whatever_model_it_stored(self):
        existing = SimpleNamespace(
            unique_id="f0:f5:bd:c4:a2:16",
            entry_id="kids",
            source="bluetooth",
            disabled_by=None,
            title="Kids Bath",
            state=State.LOADED,
            data={"transport": "ble", "address": "F0:F5:BD:C4:A2:16", "model": None},
        )
        handler = Flow([existing], dict(KIDS_BATH))
        with self.assertRaisesRegex(AbortFlow, "already_configured"):
            await handler._async_network_discovery()
        self.assertEqual(existing.data["transport"], "net")
        self.assertEqual(existing.data["model"], "SP530E")
        self.assertEqual(existing.data["host"], "10.10.30.174")
        self.assertEqual(handler.hass.config_entries.reloaded, ["kids"])


class BluetoothConfirmTests(unittest.TestCase):
    def flow(self, sweep):
        handler = Flow([], None)
        handler.hass.data = {"uniled": {"uniled_discovery": sweep}}
        handler.context = {
            "transport": "ble",
            "address": "F0:F5:BD:C4:A2:16",
            "model": None,
            "title_placeholders": {"name": "Kids Bath"},
        }
        return handler

    def test_ble_card_for_swept_sp530e_creates_network_entry(self):
        result = self.flow([dict(KIDS_BATH)])._async_bluetooth_create_entry()
        self.assertEqual(result["data"]["transport"], "net")
        self.assertEqual(result["data"]["host"], "10.10.30.174")
        self.assertEqual(result["data"]["model"], "SP530E")

    def test_ble_card_without_sweep_match_stays_ble(self):
        result = self.flow([])._async_bluetooth_create_entry()
        self.assertEqual(result["data"]["transport"], "ble")


if __name__ == "__main__":
    unittest.main()
