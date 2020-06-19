#!/usr/bin/env pluginwrapper3

import logging
import json
from datetime import datetime
from copy import deepcopy
from base64 import urlsafe_b64decode

import jwt
import requests

logger = logging.getLogger(__name__)


class Client:
    API_VERSION = 4.9
    JWS_ALG = "HS256"

    @classmethod
    def from_config(cls, configuration):
        url = configuration.get("pingid", "idp_url", required=True)
        alias = configuration.get("pingid", "org_alias", required=True)
        token = configuration.get("pingid", "token", required=True)
        key = urlsafe_b64decode(configuration.get("pingid", "base64_key", required=True))

        return cls(url, alias, token, key)

    def __init__(self, url, alias, token, key):
        self.base_url = url
        self.alias = alias
        self.token = token
        self.key = key

        self.jwt_headers = {
            "alg": self.JWS_ALG,
            "org_alias": self.alias,
            "token": self.token
        }
        self.http_headers = {
            "Content-Type": "application/json"
        }

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
            logger.debug("Response received; status_code=%i; reason=%s; response=%s",
                         response.status_code, response.reason, content)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise HTTPError(e, content=content)
        except requests.exceptions.RequestException as e:
            raise CommunicationError(e) from e

        return content

    def auth_start(self, username, device_id=None):
        params = {}
        params.update({"deviceId": device_id} if device_id else {})
        return self._call_api("/rest/4/startauthentication/do", username, params)

    def auth_online(self, username, device_id=None, request_otp=False, sp_name=None, sp_logo=None):
        params = {}
        params.update({"deviceId": device_id} if device_id else {})
        params.update({"authType": "OTP"} if request_otp else {})

        params.update({"formParameters": {}})
        params["formParameters"].update({"sp_name": sp_name} if sp_name else {})
        params["formParameters"].update({"sp_logo": sp_logo} if sp_logo else {})

        return self._call_api("/rest/4/authonline/do", username, params)

    def auth_offline(self, username, otp, session_id):
        params = {}
        params.update({"otp": otp})
        params.update({"sessionId": session_id})
        return self._call_api("/rest/4/authoffline/do", username, params)


class ClientError(Exception):
    """Base exception class for all PingID Client library related exceptions.
       It should be subclassed and not raised directly."""
    pass


class CommunicationError(ClientError, requests.exceptions.RequestException):
    pass


class HTTPError(ClientError):
    def __init__(self, *args, **kwargs):
        self.content = kwargs.pop("content", None)
        super().__init__(*args, **kwargs)


class ResponseError(Exception):
    pass
