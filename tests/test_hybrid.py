"""Exercise failover without requiring Home Assistant or physical radios."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "uniled_hybrid", Path(__file__).parents[1] / "custom_components/uniled/lib/hybrid.py"
)
hybrid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hybrid)


class Device:
    def __init__(self, name, results):
        self.name = name
        self.transport = name
        self.channel_list = [object()]
        self._channels = self.channel_list
        self.results = list(results)
        self.callbacks = []
        self.commands = []
        self.stops = 0

    def register_callback(self, callback):
        self.callbacks.append(callback)
        return lambda: self.callbacks.remove(callback)

    async def startup(self, event=None):
        return True

    async def update(self, retry=None):
        return self.results.pop(0)

    async def stop(self):
        self.stops += 1

    async def shutdown(self):
        await self.stop()

    async def async_set_state(self, channel, attr, state):
        self.commands.append((channel, attr, state))
        return False


class HybridTests(unittest.IsolatedAsyncioTestCase):
    async def test_fails_over_and_recovers_without_changing_channels(self):
        network = Device("net", [False, True])
        fallback = Device("ble", [True, True])

        async def make_fallback():
            return fallback

        device = hybrid.HybridDevice(network, make_fallback)
        channel = device.channel_list[0]
        self.assertTrue(await device.update())
        self.assertIs(device._active, fallback)
        self.assertIs(fallback._channels, network.channel_list)
        self.assertIs(device.channel_list[0], channel)
        self.assertEqual(device.transport, "net")
        self.assertFalse(await device.async_set_state(channel, "power", True))
        self.assertEqual(len(fallback.commands), 1)
        self.assertEqual(network.commands, [])
        self.assertTrue(await device.update())
        device._next_network_attempt = 0
        self.assertTrue(await device.update())
        self.assertIs(device._active, network)
        self.assertGreaterEqual(fallback.stops, 1)
        await device.shutdown()
        self.assertFalse(device.available)

    async def test_missing_fallback_remains_unavailable(self):
        network = Device("net", [False])

        async def absent():
            return None

        device = hybrid.HybridDevice(network, absent)
        self.assertFalse(await device.update())
        self.assertFalse(device.available)
        await device.shutdown()
