from textwrap import dedent

import pytest

from safeguard.sessions.plugin_impl.tasks.common_conftest import *
from safeguard.sessions.plugin_impl.tasks.common_conftest import site_parameters, interactive


@pytest.fixture
def pingid_idp_url(site_parameters):
    return site_parameters["idp_url"]

@pytest.fixture
def pingid_org_alias(site_parameters):
    return site_parameters["org_alias"]

@pytest.fixture
def pingid_token(site_parameters):
    return site_parameters["token"]

@pytest.fixture
def pingid_b64key(site_parameters):
    return site_parameters["base64_key"]

@pytest.fixture
def pingid_logo_url(site_parameters):
    return site_parameters["logo_url"]

@pytest.fixture
def pingid_selection(site_parameters):
    return site_parameters["enable_device_selection"]

@pytest.fixture
def mapped_user_id(site_parameters):
    return site_parameters["mapped_user_id"]

@pytest.fixture(scope="function")
def plugin_config(pingid_idp_url, pingid_org_alias, pingid_token, pingid_b64key,
                  pingid_logo_url, pingid_selection, mapped_user_id):
    return dedent(
        """
        [pingid]
        idp_url={pingid_idp_url}
        org_alias={pingid_org_alias}
        token={pingid_token}
        base64_key={pingid_b64key}
        logo_url={pingid_logo_url}
        enable_device_selection={pingid_selection}

        [usermapping source=explicit]
        gwuser={mapped_user_id}
        """.format_map(locals())
    )

@pytest.fixture
def connection():
    def func(otp=None, dev=None, devs=None, user="gwuser"):
            kv_pairs = {}
            kv_pairs.update({"otp": otp} if otp is not None else {})
            kv_pairs.update({"selected_device": dev} if dev is not None else {})
            cookie = {}
            cookie.update({"_device_index_map": devs} if devs is not None else {})
            return {
                "client_hostname": "localhost",
                "client_ip": "127.0.0.1",
                "client_port": 22,
                "gateway_user": user,
                "gateway_domain": "gw.domain",
                "server_username": "user",
                "server_domain": "server.domain",
                "connection_name": "test-connection",
                "session_id": "test-session-12345",
                "protocol": "ssh",
                "cookie": cookie,
                "session_cookie": {},
                "key_value_pairs": kv_pairs
            }
    return func
