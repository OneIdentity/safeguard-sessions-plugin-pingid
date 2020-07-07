#!/usr/bin/env pluginwrapper3


from safeguard.sessions.plugin import AAPlugin, AAResponse
from safeguard.sessions.plugin.exceptions import PluginSDKValueError
from safeguard.sessions.plugin.plugin_base import cookie_property

from .pingid import Client, ResponseError


class Plugin(AAPlugin):
    def __init__(self, configuration, client=None):
        super().__init__(configuration)

        self._selection = self.plugin_configuration.getboolean("pingid", "enable_device_selection", default=True)
        self._stacktrace = self.plugin_configuration.getboolean("logging", "enable_stacktrace", default=False)

        self._client = client

    @cookie_property
    def _device_index_map(self):
        return {}

    @property
    def _push_display_text(self):
        return "{c.protocol} from {c.client_ip} by {username}".format(c=self.connection, username=self.username)

    @property
    def username(self):
        return self.connection.gateway_username or self.connection.server_username

    def do_authenticate(self):
        reason = None
        self._client = self._client or Client.from_config(
            self.plugin_configuration, self._get_device_id(), self._push_display_text
        )
        try:
            return self._dispatch()
        except InvalidDeviceSelection as e:
            self.logger.info("Invalid device selected: %s", e)
            reason = "Invalid device selected."
        except ResponseError as e:
            self.logger.error("Invalid response: %s", e, exc_info=self._stacktrace)
            reason = "Invalid response from PingID API."
        except Exception as e:
            self.logger.error("Unexpected error: %s: %s", type(e), e, exc_info=self._stacktrace)

        return AAResponse.deny(reason=reason)

    def _get_device_id(self):
        device_index = self._get_device_index()
        if device_index in self._device_index_map:
            return self._device_index_map[device_index]

        if device_index is not None:
            raise InvalidDeviceSelection(message="selection={}".format(device_index))

    def _get_device_index(self):
        return self.connection.key_value_pairs.get("selected_device")

    def _get_devices(self):
        response = self._client.auth_start(self.mfa_identity)
        return response.get("responseBody").get("userDevices", [])

    def _select_device(self):
        if not self._selection:
            self.logger.info("Device selection disabled, rejecting connection")
            return AAResponse.deny(reason="Device selection disabled")

        devices = self._get_devices()
        if not devices:
            self.logger.info("No devices to select from, rejecting connection")
            return AAResponse.deny(reason="No devices to select from")

        message = ""
        self._device_index_map = {}
        for position, device in enumerate(devices, start=1):
            message += "{}) {}\n".format(position, device["nickname"])
            self._device_index_map[position] = device["deviceId"]

        message += "Please select a device: "

        self.logger.debug("Prompting user to select a device; device_ids=%s", self._device_index_map)
        return AAResponse.need_info(message, "selected_device")

    def _get_auth_info(self):
        self.connection.key_value_pairs.pop("otp")
        self.logger.debug("Prompting for MFA input")
        return self._ask_mfa_password()

    def _dispatch(self):
        if self.mfa_password == "!select":
            device_id = self._get_device_id()
            if device_id is not None:
                self.logger.info("Device selected; device_id=%s", device_id)
                return self._get_auth_info()

            self.logger.info("Device selection command received")
            return self._select_device()

        return self._client.execute_authenticate(self.username, self.mfa_identity, self.mfa_password)


class InvalidDeviceSelection(PluginSDKValueError):
    pass
