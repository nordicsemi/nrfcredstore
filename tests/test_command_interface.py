from unittest.mock import patch, Mock
from collections import namedtuple
import pytest

import base64

from nrfcredstore.command_interface import (CredentialCommandInterface, ATCommandInterface,
                                            TLSCredShellInterface, TLSCredKeygenShellInterface,
                                            NrfCloudCredShellInterface)
from nrfcredstore.credstore import CredType

@pytest.fixture
def comms():
    """Mock comms object"""
    comms = Mock()
    return comms

@pytest.fixture
def at_command_interface(comms):
    """Mock command interface"""
    interface = ATCommandInterface(comms)
    return interface

@pytest.fixture
def tls_cred_shell_interface(comms):
    """Mock TLSCredShellInterface"""
    interface = TLSCredShellInterface(comms)
    return interface

def test_write_raw_at(at_command_interface):
    """Test writing raw AT commands"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.write_raw('AT+TEST=1')
    at_command_interface.comms.write_line.assert_called_once_with('AT+TEST=1')

def test_write_raw_tls(tls_cred_shell_interface):
    """Test writing raw TLS commands"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.write_raw('AT+TEST=1')
    tls_cred_shell_interface.comms.write_line.assert_called_once_with('AT+TEST=1')

def test_write_credential_at(at_command_interface):
    """Test writing a credential using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, "")
    at_command_interface.write_credential(sectag=42, cred_type=CredType.CLIENT_CERT.value, cred_text='test_value')
    at_command_interface.comms.write_line.assert_called_once_with('AT%CMNG=0,42,1,"test_value"')

def test_delete_credential_at(at_command_interface):
    """Test deleting a credential using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, "")
    at_command_interface.delete_credential(sectag=42, cred_type=CredType.CLIENT_CERT.value)
    at_command_interface.comms.write_line.assert_called_once_with('AT%CMNG=3,42,1')

def test_delete_credential_tls(tls_cred_shell_interface):
    """Test deleting a credential that exists in TLS shell"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.return_value = (True, '')
    tls_cred_shell_interface.delete_credential(sectag=42, cred_type=CredType.ROOT_CA_CERT.value)
    tls_cred_shell_interface.comms.write_line.assert_called_once_with('cred del 42 CA')

def test_delete_credential_tls_not_found(tls_cred_shell_interface):
    """Test deleting a credential that does not exist in TLS shell"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.return_value = (False, '')
    tls_cred_shell_interface.delete_credential(sectag=42, cred_type=CredType.ROOT_CA_CERT.value)
    tls_cred_shell_interface.comms.write_line.assert_called_once_with('cred del 42 CA')

def test_check_credential_exists_tls(tls_cred_shell_interface):
    """Test checking a credential that exists in TLS shell"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.return_value = (True, '42,CA,qLqL2kIyuj7FF9aFXQuhmc8kbMOHNYsM451gElqNyVQ=,0\r\n')
    result, hash = tls_cred_shell_interface.check_credential_exists(sectag=42, cred_type=CredType.ROOT_CA_CERT.value, get_hash=True)
    tls_cred_shell_interface.comms.write_line.assert_called_once_with('cred list 42 CA')
    assert hash == 'qLqL2kIyuj7FF9aFXQuhmc8kbMOHNYsM451gElqNyVQ='
    assert result == True

def test_check_credential_exists_tls_not_found(tls_cred_shell_interface):
    """Test checking a credential that does not exist in TLS shell"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.return_value = (False, '')
    result, hash = tls_cred_shell_interface.check_credential_exists(sectag=42, cred_type=CredType.ROOT_CA_CERT.value, get_hash=True)
    tls_cred_shell_interface.comms.write_line.assert_called_once_with('cred list 42 CA')
    assert hash == None
    assert result == False

def test_write_credential_tls(tls_cred_shell_interface):
    """Test writing a credential using TLSCredShellInterface"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.side_effect = [
        (True, ""),
        (True, "")
    ]
    result = tls_cred_shell_interface.write_credential(sectag=42, cred_type=CredType.CLIENT_CERT.value, cred_text='test_value')
    assert result == True
    assert tls_cred_shell_interface.comms.write_line.call_count >= 3


def test_check_credential_exists_at(at_command_interface):
    """Test checking if a credential exists using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '%CMNG: 42,1,"8CEA57609B0F95C0D0F80383A7A21ECD1C6E102FDCC3CDCEB1948B0EA828601D"')
    exists, sha = at_command_interface.check_credential_exists(sectag=42, cred_type=CredType.CLIENT_CERT.value)
    assert exists is True
    assert sha == '8CEA57609B0F95C0D0F80383A7A21ECD1C6E102FDCC3CDCEB1948B0EA828601D'

def test_get_csr_at(at_command_interface):
    """Test getting a CSR using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '%KEYGEN: "foo.bar"')
    csr = at_command_interface.get_csr(sectag=42, attributes='O=Test,CN=Device')
    assert csr == 'foo.bar'
    at_command_interface.comms.write_line.assert_called_once_with('AT%KEYGEN=42,2,0,"O=Test,CN=Device"')

def test_get_csr_no_attributes(at_command_interface):
    """Test getting a CSR without attributes using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '%KEYGEN: "foo.bar"')
    csr = at_command_interface.get_csr(sectag=42)
    assert csr == 'foo.bar'
    at_command_interface.comms.write_line.assert_called_once_with('AT%KEYGEN=42,2,0')

def test_get_imei(at_command_interface):
    """Test getting IMEI using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '123456789012345')
    imei = at_command_interface.get_imei()
    assert imei == '123456789012345'
    at_command_interface.comms.write_line.assert_called_once_with('AT+CGSN')

def test_go_offline(at_command_interface):
    """Test going offline using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '')
    at_command_interface.go_offline()
    at_command_interface.comms.write_line.assert_called_once_with('AT+CFUN=4')

def test_get_model_id(at_command_interface):
    """Test getting model ID using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, 'nRF9151-LACA')
    model_id = at_command_interface.get_model_id()
    assert model_id == 'nRF9151-LACA'
    at_command_interface.comms.write_line.assert_called_once_with('AT+CGMM')

def test_get_mfw_version(at_command_interface):
    """Test getting MFW version using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, 'mfw_nrf91x1_2.0.2')
    mfw_version = at_command_interface.get_mfw_version()
    assert mfw_version == 'mfw_nrf91x1_2.0.2'
    at_command_interface.comms.write_line.assert_called_once_with('AT+CGMR')

def test_get_attestation_token(at_command_interface):
    """Test getting attestation token using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '%ATTESTTOKEN: "foo.bar"')
    attestation_token = at_command_interface.get_attestation_token()
    assert attestation_token == 'foo.bar'
    at_command_interface.comms.write_line.assert_called_once_with('AT%ATTESTTOKEN')

def test_enable_error_codes(at_command_interface):
    """Test enabling error codes using ATCommandInterface"""
    at_command_interface.comms.write_line = Mock()
    at_command_interface.comms.expect_response.return_value = (True, '')
    at_command_interface.enable_error_codes()
    at_command_interface.comms.write_line.assert_called_once_with('AT+CMEE=1')

class MockCommsAT:
    """Mock comms for ATCommandInterface"""
    def write_line(self, line):
        self.last_written = line

    def expect_response(self, ok_str=None, error_str=None, store_str=None, timeout=15, suppress_errors=False):
        if self.last_written == 'AT+CGSN':
            return True, '123456789012345'
        else:
            return False, ''

def test_detect_shell_mode_at(at_command_interface):
    """Test detecting shell mode using ATCommandInterface (AT Host)"""
    at_command_interface.comms = MockCommsAT()
    at_command_interface.detect_shell_mode()
    assert at_command_interface.shell == False

class MockCommsATShell:
    """Mock comms for TLSCredShellInterface"""
    def write_line(self, line):
        self.last_written = line

    def expect_response(self, ok_str=None, error_str=None, store_str=None, timeout=15, suppress_errors=False):
        if self.last_written == 'at AT+CGSN':
            return True, '123456789012345'
        else:
            return False, ''

def test_detect_shell_mode_shell(at_command_interface):
    """Test detecting shell mode using ATCommandInterface (AT Shell)"""
    at_command_interface.comms = MockCommsATShell()
    at_command_interface.detect_shell_mode()
    assert at_command_interface.shell == True


@pytest.fixture
def keygen_interface(comms):
    """Mock TLSCredKeygenShellInterface"""
    return TLSCredKeygenShellInterface(comms)

@pytest.fixture
def nrf_cloud_cred_interface(comms):
    """Mock NrfCloudCredShellInterface"""
    return NrfCloudCredShellInterface(comms)

def written_lines(interface):
    return [c.args[0] for c in interface.comms.write_line.call_args_list]

def test_keygen_get_csr(keygen_interface):
    """Test the key is generated, then the CSR is read from the TLS credentials shell"""
    keygen_interface.comms.expect_response.side_effect = [
        (True, ''),
        (True, 'CSR: MIIB==\r\n'),
    ]
    csr = keygen_interface.get_csr(sectag=42, attributes='CN=my-device,O=Nordic')
    assert csr == 'MIIB=='
    assert written_lines(keygen_interface) == [
        'cred keygen 42',
        'cred csr 42 "CN=my-device,O=Nordic"',
    ]

def test_keygen_get_csr_existing_key(keygen_interface):
    """Test an existing key is not an error, the CSR is still read"""
    keygen_interface.comms.expect_response.side_effect = [
        (False, ''),
        (True, 'CSR: MIIB==\r\n'),
    ]
    assert keygen_interface.get_csr(sectag=42, attributes='CN=a') == 'MIIB=='

def test_keygen_get_csr_requires_subject(keygen_interface):
    """Test no command is sent when the subject is missing"""
    assert keygen_interface.get_csr(sectag=42) is None
    keygen_interface.comms.write_line.assert_not_called()

def test_keygen_get_csr_failure(keygen_interface):
    """Test a failed CSR generation returns None"""
    keygen_interface.comms.expect_response.side_effect = [(True, ''), (False, '')]
    assert keygen_interface.get_csr(sectag=42, attributes='CN=a') is None

def test_keygen_get_csr_missing_output(keygen_interface):
    """Test a missing CSR line returns None"""
    keygen_interface.comms.expect_response.side_effect = [(True, ''), (True, '')]
    assert keygen_interface.get_csr(sectag=42, attributes='CN=a') is None

def test_keygen_delete_private_key(keygen_interface):
    """Test the private key is deleted with the key command"""
    keygen_interface.comms.expect_response.return_value = (True, '')
    assert keygen_interface.delete_credential(42, CredType.CLIENT_KEY.value) is True
    assert written_lines(keygen_interface) == ['cred keydel 42']

def test_keygen_delete_certificate(keygen_interface):
    """Test certificates are deleted with the regular credential command"""
    keygen_interface.comms.expect_response.return_value = (True, '')
    keygen_interface.delete_credential(42, CredType.ROOT_CA_CERT.value)
    assert written_lines(keygen_interface) == ['cred del 42 CA']

def test_keygen_get_pubkey(keygen_interface):
    """Test the public key is decoded from the shell output"""
    pubkey = b'\x04' + bytes(range(64))
    keygen_interface.comms.expect_response.return_value = (
        True, 'PUBKEY: ' + base64.b64encode(pubkey).decode() + '\r\n')
    assert keygen_interface.get_pubkey(42) == pubkey
    assert written_lines(keygen_interface) == ['cred pubkey 42']

def test_keygen_get_pubkey_failure(keygen_interface):
    """Test a failed public key export returns None"""
    keygen_interface.comms.expect_response.return_value = (False, '')
    assert keygen_interface.get_pubkey(42) is None

def test_nrf_cloud_cred_get_csr_with_attributes(nrf_cloud_cred_interface):
    """Test the nrf_cloud_cred commands are used with a subject"""
    nrf_cloud_cred_interface.comms.expect_response.side_effect = [
        (True, ''),
        (True, 'CSR: MIIB==\r\n'),
    ]
    assert nrf_cloud_cred_interface.get_csr(sectag=42, attributes='CN=dev') == 'MIIB=='
    assert written_lines(nrf_cloud_cred_interface) == [
        'nrf_cloud_cred keygen 42',
        'nrf_cloud_cred csr 42 "CN=dev"',
    ]

def test_nrf_cloud_cred_get_csr_default_subject(nrf_cloud_cred_interface):
    """Test the nrf_cloud_cred shell chooses the subject when none is given"""
    nrf_cloud_cred_interface.comms.expect_response.side_effect = [
        (True, ''),
        (True, 'CSR: MIIB==\r\n'),
    ]
    assert nrf_cloud_cred_interface.get_csr(sectag=42) == 'MIIB=='
    assert written_lines(nrf_cloud_cred_interface) == [
        'nrf_cloud_cred keygen 42',
        'nrf_cloud_cred csr 42',
    ]

def test_nrf_cloud_cred_delete_private_key(nrf_cloud_cred_interface):
    """Test the private key is deleted with the nrf_cloud_cred command"""
    nrf_cloud_cred_interface.comms.expect_response.return_value = (True, '')
    nrf_cloud_cred_interface.delete_credential(42, CredType.CLIENT_KEY.value)
    assert written_lines(nrf_cloud_cred_interface) == ['nrf_cloud_cred delete 42']

def test_nrf_cloud_cred_get_pubkey(nrf_cloud_cred_interface):
    """Test the nrf_cloud_cred public key command"""
    pubkey = b'\x04' + bytes(64)
    nrf_cloud_cred_interface.comms.expect_response.return_value = (
        True, 'PUBKEY: ' + base64.b64encode(pubkey).decode())
    assert nrf_cloud_cred_interface.get_pubkey(42) == pubkey
    assert written_lines(nrf_cloud_cred_interface) == ['nrf_cloud_cred pubkey 42']

def test_write_credential_tls_buffer_full(tls_cred_shell_interface):
    """Test that a full credential buffer on the device fails instead of storing a truncated credential"""
    tls_cred_shell_interface.comms.write_line = Mock()
    tls_cred_shell_interface.comms.expect_response.return_value = (False, '')
    assert tls_cred_shell_interface.write_credential(42, CredType.CLIENT_CERT.value, 'x' * 200) is False
    # Stops at the first chunk that failed: clear the buffer and send one chunk.
    assert tls_cred_shell_interface.comms.write_line.call_count == 2
