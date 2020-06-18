import pytest
import requests

from safeguard.sessions.plugin_impl.tasks.common_conftest import interactive

from ..plugin import Plugin


@pytest.fixture(scope="function")
def plugin(plugin_config):
    return Plugin(plugin_config)

def test_push_auth_accept_with_primary_device(plugin, connection, interactive):
    assert plugin.authenticate(**connection()).get("verdict") == "NEEDINFO"

    interactive.message("Please accept the PUSH notification")
    assert plugin.authenticate(**connection(otp="")).get("verdict") == "ACCEPT"

def test_push_auth_reject_with_primary_device(plugin, connection, interactive):
    assert plugin.authenticate(**connection()).get("verdict") == "NEEDINFO"

    interactive.message("Please reject the PUSH notification")
    assert plugin.authenticate(**connection(otp="")).get("verdict") == "DENY"

def test_push_auth_invalid_api_key(plugin, connection, interactive):
    plugin._client.key = ""
    assert plugin.authenticate(**connection(otp="")).get("verdict") == "DENY"

def test_push_auth_not_available(plugin, connection, interactive):
    resp = plugin.authenticate(**connection(otp="!select"))
    devs = resp.get("cookie").get("_device_index_map")
    interactive.message("Select a device that doesn't support PUSH notificatons")
    dev = interactive.askforinput("\n{}".format(resp["question"][1]))
    assert plugin.authenticate(**connection(otp="", dev=dev, devs=devs)).get("verdict") == "DENY"

def test_push_auth_connection_error(plugin, connection, mocker):
    post = mocker.patch("requests.post")
    post.side_effect = requests.exceptions.RequestException
    assert plugin.authenticate(**connection(otp="")).get("verdict") == "DENY"

def test_push_invalid_response(plugin, connection, mocker):
    with mocker.patch("requests.post", return_value=mocker.Mock(content=b'')):
        assert plugin.authenticate(**connection(otp="")).get("verdict") == "DENY"

def test_push_unexpected_exception(plugin, connection, mocker):
    with mocker.patch("requests.post", side_effect=RuntimeError):
        assert plugin.authenticate(**connection(otp="")).get("verdict") == "DENY"

def test_otp_auth_valid_with_primary_device(plugin, connection, interactive):
    otp = interactive.askforinput("Please enter your OTP")
    assert plugin.authenticate(**connection(otp=otp)).get("verdict") == "ACCEPT"

def test_otp_auth_invalid_with_primary_device(plugin, connection, interactive):
    assert plugin.authenticate(**connection(otp=12345)).get("verdict") == "DENY"

def test_otp_unkown_username(plugin, connection):
    assert plugin.authenticate(**connection(otp=12345, user="unknown")).get("verdict") == "DENY"

def test_dev_selection_command(plugin, connection):
    assert plugin.authenticate(**connection(otp="!select")).get("verdict") == "NEEDINFO"

def test_dev_selection_valid_input(plugin, connection):
    assert plugin.authenticate(**connection(otp="!select", dev=1, devs={1:1, 2:2})).get("verdict") == "NEEDINFO"

def test_dev_selection_invalid_input(plugin, connection):
    assert plugin.authenticate(**connection(otp="!select", dev=0, devs={1:1, 2:2})).get("verdict") == "DENY"
    assert plugin.authenticate(**connection(otp="!select", dev="", devs={1:1, 2:2})).get("verdict") == "DENY"

def test_dev_selection_no_devices(plugin, connection, mocker):
    plugin._get_devices = mocker.Mock()
    plugin._get_devices.return_value = []
    assert plugin.authenticate(**connection(otp="!select")).get("verdict") == "DENY"

def test_dev_selection_disabled(plugin, connection):
    plugin._selection = False
    assert plugin.authenticate(**connection(otp="!select")).get("verdict") == "DENY"
