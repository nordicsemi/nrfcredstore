from typing_extensions import assert_type

from nrfcredstore.command_interface import (
    ATCommandInterface,
    TLSCredKeygenShellInterface,
)
from nrfcredstore.comms import Comms
from nrfcredstore.credstore import CredStore, Credential, CredType
from nrfcredstore.csr import normalize_ecdsa_csr_der
from nrfcredstore.exceptions import RTTUnavailableError


def check_consumer(comms: Comms, at: ATCommandInterface, shell: TLSCredKeygenShellInterface,
                   store: CredStore, error: RTTUnavailableError) -> None:
    assert_type(comms.expect_response("OK", "ERROR", timeout=2.5), tuple[bool, str])
    assert_type(at.at_command("AT", wait_for_result=True), bool)
    assert_type(at.get_csr(1234), str | None)
    assert_type(at.get_attestation_token(), str | None)
    assert_type(shell.get_pubkey(1234), bytes | None)
    assert_type(store.list(1234, CredType.CLIENT_CERT), list[Credential])
    assert_type(normalize_ecdsa_csr_der(b""), bytes)
    assert_type(error, RTTUnavailableError)
