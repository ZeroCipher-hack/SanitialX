"""
Sensor manager for SentinelX.

Manages the lifecycle of multiple :class:`BaseSensor` instances.
No module-level mutable singletons — the manager must be instantiated
explicitly.
"""

from __future__ import annotations

from typing import Any

from sensors.base import BaseSensor


class SensorManager:
    """Manages registration, lifecycle, and health of sensors.

    Usage::

        manager = SensorManager()
        manager.register(my_sensor)
        await manager.start_all()
        ...
        await manager.stop_all()
    """

    def __init__(self) -> None:
        self._sensors: dict[str, BaseSensor] = {}

    def register(self, sensor: BaseSensor) -> None:
        """Register a sensor. Raises ValueError on duplicate sensor_id."""
        if sensor.sensor_id in self._sensors:
            raise ValueError(
                f"Sensor with id '{sensor.sensor_id}' is already registered"
            )
        self._sensors[sensor.sensor_id] = sensor

    def unregister(self, sensor_id: str) -> None:
        """Unregister a sensor by id. Raises KeyError if not found."""
        if sensor_id not in self._sensors:
            raise KeyError(f"Sensor '{sensor_id}' is not registered")
        del self._sensors[sensor_id]

    async def start_all(self) -> None:
        """Start all registered sensors."""
        for sensor in self._sensors.values():
            await sensor.start()

    async def stop_all(self) -> None:
        """Stop all registered sensors."""
        for sensor in self._sensors.values():
            if sensor.is_running():
                await sensor.stop()

    def health_all(self) -> dict[str, dict[str, Any]]:
        """Return health info for all registered sensors."""
        return {
            sensor_id: sensor.health()
            for sensor_id, sensor in self._sensors.items()
        }

    @property
    def sensors(self) -> dict[str, BaseSensor]:
        """Read-only view of registered sensors."""
        return dict(self._sensors)
