#!/usr/bin/env pluginwrapper3


from safeguard.sessions.plugin import AAPlugin, AAResponse
from safeguard.sessions.plugin.plugin_base import cookie_property

from .pingid import Client, ResponseError, HTTPError, CommunicationError


class Plugin(AAPlugin):
    def __init__(self, configuration, client=None):
        super().__init__(configuration)

        self._logo_url = self.plugin_configuration.get("pingid", "logo_url", default=None)
        self._selection = self.plugin_configuration.getboolean("pingid", "enable_device_selection", default=True)
        self._stacktrace = self.plugin_configuration.getboolean("logging", "enable_stacktrace", default=False)

        self._client = client or Client.from_config(self.plugin_configuration)

    @cookie_property
    def _device_index_map(self):
        return {}

    @property
    def _push_display_text(self):
        username = self.connection.gateway_username or self.connection.server_username
        return "{c.protocol} from {c.client_ip} by {username}".format(c=self.connection, username=username)

    def _get_device_id(self):
        device_index = self._get_device_index()
        if device_index in self._device_index_map:
            return self._device_index_map[device_index]

        if device_index is not None:
            raise InvalidDeviceSelection("selection={}".format(device_index))

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

        position = 0
        message = ""
        self._device_index_map = {}
        for device in devices:
            position += 1
            message += "{}) {}\n".format(position, device["nickname"])
            self._device_index_map.update(position=device["deviceId"])
        message += "Please select a device: "

        self.logger.debug("Prompting user to select a device; device_ids=%s",
                          self._device_index_map)
        return AAResponse.need_info(message, "selected_device")

    def _get_auth_info(self):
        self.connection.key_value_pairs.pop("otp")
        self.logger.debug("Prompting for MFA input")
        return self._ask_mfa_password()

    def _extract_info(self, response, key):
        return response.get("responseBody", {}).get(key)

    def _get_reason(self, response):
        # See this link for more info:
        # https://apidocs.pingidentity.com/pingid-api/guide/pingid-api/pid_c_PingIDapiErrorCodes/
        response_id = self._extract_info(response, "errorId")
        if response_id in range(2500, 2600) or response_id in range(30000, 30015):
            return self._extract_info(response, "errorMsg")

    def _get_verdict(self, response):
        response_id = self._extract_info(response, "errorId")
        response_msg = self._extract_info(response, "errorMsg")

        if response_id == 200:
            self.logger.info("Authentication successful")
            return AAResponse.accept(reason="Authentication successful")

        self.logger.info("Authentication failure; id=%i, msg=%s", response_id, response_msg)
        return AAResponse.deny(reason=self._get_reason(response))

    def _otp_authenticate(self):
        response = self._client.auth_online(self.mfa_identity, self._get_device_id(), request_otp=True)
        session_id = self._extract_info(response, "sessionId")
        response = self._client.auth_offline(self.mfa_identity, self.mfa_password, session_id)

        return self._get_verdict(response)

    def _push_authenticate(self):
        response = self._client.auth_online(self.mfa_identity, self._get_device_id(),
                                            sp_name=self._push_display_text, sp_logo=self._logo_url)
        return self._get_verdict(response)

    def _dispatch(self):
        if self.mfa_password == "!select":
            device_id = self._get_device_id()
            if device_id is not None:
                self.logger.info("Device selected; device_id=%s", device_id)
                return self._get_auth_info()

            self.logger.info("Device selection command received")
            return self._select_device()

        if self.mfa_password:
            self.logger.info("Authenticating with OTP")
            return self._otp_authenticate()

        self.logger.info("Authenticating with PUSH notification")
        return self._push_authenticate()

    def do_authenticate(self):
        reason = None
        try:
            return self._dispatch()
        except InvalidDeviceSelection as e:
            self.logger.info("Invalid device selected: %s", e)
        except ResponseError as e:
            self.logger.error("Invalid response: %s", e, exc_info=self._stacktrace)
        except HTTPError as e:
            reason = self._get_reason(e.content)
            self.logger.info("Authentication failure: %s, msg=%s", e,
                             self._extract_info(e.content, "errorMsg"))
        except CommunicationError as e:
            self.logger.error("Connection failure: %s", e, exc_info=self._stacktrace)
        except Exception as e:
            self.logger.error("Unexpected error: %s: %s", type(e), e, exc_info=self._stacktrace)

        return AAResponse.deny(reason=reason)


class PluginError(Exception):
    pass


class InvalidDeviceSelection(PluginError):
    pass
