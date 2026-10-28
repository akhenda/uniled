"""Transport selection for a single dual-transport controller."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import logging
import time
from typing import Any

_LOGGER = logging.getLogger(__name__)
NETWORK_RETRY_SECONDS = 120


class HybridDevice:
    """Keep network entities stable while selecting a working connection.

    The fallback factory must return a verified BLE device for the same physical
    controller, or None when no connectable advertisement is available.
    """

    def __init__(self, network: Any, fallback_factory: Callable[[], Awaitable[Any]]):
        self._network = network
        self._fallback_factory = fallback_factory
        self._fallback = None
        self._active = network
        self._started = True
        self._available = False
        self._next_network_attempt = 0.0
        self._lock = asyncio.Lock()
        self._callbacks: list[Callable] = []
        self._unregister = [network.register_callback(self._fire_callbacks)]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._active, name)

    @property
    def channel_list(self):
        return self._network.channel_list

    @property
    def available(self) -> bool:
        return self._available

    @property
    def started(self) -> bool:
        return self._started

    @property
    def transport(self) -> str:
        # Registry identity must not change when the active link changes.
        return self._network.transport

    def register_callback(self, callback: Callable) -> Callable:
        self._callbacks.append(callback)

        def unregister() -> None:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

        return unregister

    def _fire_callbacks(self, *_: Any) -> None:
        for callback in tuple(self._callbacks):
            callback(self)

    async def startup(self, event=None) -> bool:
        self._started = True
        return await self._network.startup(event)

    async def _get_fallback(self):
        if self._fallback is None:
            fallback = await self._fallback_factory()
            if fallback is None:
                return None
            if len(fallback.channel_list) != len(self.channel_list):
                await fallback.shutdown()
                return None
            # Existing entities hold channel references. Both parsers must update
            # the original channels, rather than replacing those references.
            fallback._channels = self._network.channel_list
            self._fallback = fallback
            self._unregister.append(fallback.register_callback(self._fire_callbacks))
        return self._fallback

    async def _try_update(self, device, retry) -> bool:
        try:
            return bool(await device.update(retry))
        except Exception:  # transport failures should allow the other link to run
            _LOGGER.warning("%s: Transport update failed", device.name, exc_info=True)
            return False

    async def update(self, retry=None) -> bool:
        async with self._lock:
            if self._active is self._network or time.monotonic() >= self._next_network_attempt:
                if self._active is not self._network:
                    await self._active.stop()
                if await self._try_update(self._network, retry):
                    if self._active is not self._network:
                        _LOGGER.info("%s: Network connection restored", self._network.name)
                    self._active = self._network
                    self._available = True
                    return True
                await self._network.stop()
                self._next_network_attempt = time.monotonic() + NETWORK_RETRY_SECONDS

            fallback = await self._get_fallback()
            if fallback is not None and await self._try_update(fallback, retry):
                if self._active is not fallback:
                    _LOGGER.info("%s: Using Bluetooth fallback", self._network.name)
                self._active = fallback
                self._available = True
                return True
            self._available = False
            return False

    async def async_set_state(self, channel, attr, state) -> bool:
        async with self._lock:
            # A timeout may mean the device applied the command; never replay it
            # on another transport without an intervening state refresh.
            return await self._active.async_set_state(channel, attr, state)

    async def async_set_multi_state(self, channel, **kwargs) -> bool:
        async with self._lock:
            return await self._active.async_set_multi_state(channel, **kwargs)

    def get_list(self, channel, attr):
        return self._active.get_list(channel, attr)

    async def stop(self) -> None:
        async with self._lock:
            await self._network.stop()
            if self._fallback is not None:
                await self._fallback.stop()
            self._available = False

    async def shutdown(self, event=None) -> None:
        self._started = False
        await self.stop()
        for unregister in self._unregister:
            unregister()
        self._unregister.clear()

    def update_advertisement(self, service_info) -> None:
        if self._fallback is not None:
            self._fallback.set_device_and_advertisement(
                service_info.device, service_info.advertisement
            )
