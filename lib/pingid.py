#!/usr/bin/env pluginwrapper3

import json
import logging
from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import datetime

import jwt
import requests

from safeguard.sessions.plugin import AAResponse
from safeguard.sessions.plugin.mfa_client import (
    MFAClient,
    MFAAuthenticationFailure,
    MFACommunicationError,
)

logger = logging.getLogger(__name__)


class Client(MFAClient):
    API_VERSION = 4.9
    JWS_ALG = "HS256"

    @classmethod
    def from_config(cls, configuration, device_id, push_display_text):
        url = configuration.get("pingid", "idp_url", required=True)
        alias = configuration.get("pingid", "org_alias", required=True)
        token = configuration.get("pingid", "token", required=True)
        key = urlsafe_b64decode(configuration.get("pingid", "base64_key", required=True))
        logo_url = configuration.get("pingid", "logo_url", default=None)

        return cls(url, alias, token, key, logo_url, device_id, push_display_text)

    def __init__(self, url, alias, token, key, logo_url, device_id, push_display_text):
        super().__init__("SPS PingID Plugin")

        self.base_url = url
        self.alias = alias
        self.token = token
        self.key = key
        self.logo_url = logo_url
        self.device_id = device_id
        self.push_display_text = push_display_text

        self.jwt_headers = {
            "alg": self.JWS_ALG,
            "org_alias": self.alias,
            "token": self.token
        }
        self.http_headers = {
            "Content-Type": "application/json"
        }
        logger.info("Client initialized.")


    def otp_authenticate(self, mfa_identity, otp):
        response = self._auth_online(mfa_identity, request_otp=True)
        session_id = self._extract_info(response, "sessionId")
        response = self._auth_offline(mfa_identity, otp, session_id)

        return self._get_verdict(response)

    def push_authenticate(self, mfa_identity):
        response = self._auth_online(
            mfa_identity, sp_name=self.push_display_text, sp_logo=self.logo_url,
        )
        return self._get_verdict(response)

    def auth_start(self, username, device_id=None):
        params = {}
        params.update({"deviceId": device_id} if device_id else {})
        return self._call_api("/rest/4/startauthentication/do", username, params)

    def _auth_online(self, username, request_otp=False, sp_name=None, sp_logo=None):
        params = {}
        params.update({"deviceId": self.device_id} if self.device_id else {})
        params.update({"authType": "OTP"} if request_otp else {})

        params.update({"formParameters": {}})
        params["formParameters"].update({"sp_name": sp_name} if sp_name else {})
        params["formParameters"].update({"sp_logo": sp_logo} if sp_logo else {})

        return self._call_api("/rest/4/authonline/do", username, params)

    def _auth_offline(self, username, otp, session_id):
        params = {}
        params.update({"otp": otp})
        params.update({"sessionId": session_id})
        return self._call_api("/rest/4/authoffline/do", username, params)

    def _call_api(self, path, username, params):
        request = {
            "reqHeader": self._get_request_headers(),
            "reqBody": self._get_request_body(username, params)
        }
        encoded_request = self._jwt_encode(request)
        url = self.base_url + path

        logger.debug("Running API call; url=%s; headers=%s; request=%s",
                     url, self.http_headers, self._filter_request(request))
        try:
            response = requests.post(url, encoded_request, headers=self.http_headers)
            content = self._extract_json(response.content)
            logger.debug(
                "Response received; status_code=%i; reason=%s; response=%s",
                response.status_code,
                response.reason,
                content,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise MFAAuthenticationFailure(self._get_reason(content))
        except requests.exceptions.RequestException as e:
            raise MFACommunicationError(e) from e

        return content

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
            logger.info("Authentication successful")
            return AAResponse.accept(reason="Authentication successful")

        logger.info("Authentication failure; id=%i, msg=%s", response_id, response_msg)
        return AAResponse.deny(reason=self._get_reason(response))

    def _get_timestamp(self):
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Convert microsec to milisec

    def _get_request_headers(self):
        return {
            "locale": "en",
            "orgAlias": self.alias,
            "secretKey": self.token,
            "version": self.API_VERSION,
            "timestamp": self._get_timestamp()
        }

    def _filter_request(self, request):
        request = deepcopy(request)
        request["reqHeader"]["secretKey"] = "[removed]"
        return request

    def _get_request_body(self, username, params):
        return {
            "spAlias": "web",
            "userName": username,
            **params
        }

    def _jwt_encode(self, data):
        return jwt.encode(data, self.key, algorithm=self.JWS_ALG, headers=self.jwt_headers)

    def _jwt_decode(self, data):
        return jwt.decode(data, self.key, algorithms=[self.JWS_ALG])

    def _extract_json(self, data):
        try:
            return self._jwt_decode(data)
        except jwt.exceptions.InvalidTokenError:
            logger.debug("Response is not a valid JWT")
        try:
            return json.loads(data)
        except ValueError:
            raise ResponseError("Failed to JWT/JSON decode response")


class ResponseError(Exception):
    pass
