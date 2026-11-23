import base64


ECDSA_SHA256_OID_TLV = b"\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02"


def _decode_tlv_length(data, offset):
    if offset >= len(data):
        raise ValueError("Missing DER length")

    first = data[offset]
    if first < 0x80:
        return first, 1

    length_bytes = first & 0x7F
    if length_bytes == 0:
        raise ValueError("Indefinite DER length is not supported")
    if offset + 1 + length_bytes > len(data):
        raise ValueError("Truncated DER length")

    value = 0
    for index in range(length_bytes):
        value = (value << 8) | data[offset + 1 + index]
    return value, 1 + length_bytes


def _encode_tlv_length(value):
    if value < 0x80:
        return bytes([value])

    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def normalize_ecdsa_csr_der(der):
    """Remove the invalid NULL parameter from legacy nRF91 ECDSA-SHA256 CSRs."""
    if len(der) < 8 or der[0] != 0x30:
        return der

    try:
        outer_length, outer_length_header = _decode_tlv_length(der, 1)
        outer_start = 1 + outer_length_header
        outer_end = outer_start + outer_length
        if outer_end != len(der):
            return der

        cri_tag = outer_start
        if der[cri_tag] != 0x30:
            return der

        cri_length, cri_length_header = _decode_tlv_length(der, cri_tag + 1)
        cri_value_start = cri_tag + 1 + cri_length_header
        cri_end = cri_value_start + cri_length
        if cri_end > outer_end:
            return der

        sig_alg_tag = cri_end
        if sig_alg_tag >= outer_end or der[sig_alg_tag] != 0x30:
            return der

        sig_alg_length, sig_alg_length_header = _decode_tlv_length(
            der, sig_alg_tag + 1
        )
        sig_alg_value_start = sig_alg_tag + 1 + sig_alg_length_header
        sig_alg_end = sig_alg_value_start + sig_alg_length
        if sig_alg_end > outer_end:
            return der

        sig_alg_value = der[sig_alg_value_start:sig_alg_end]
        if (
            not sig_alg_value.startswith(ECDSA_SHA256_OID_TLV)
            or not sig_alg_value.endswith(b"\x05\x00")
            or len(sig_alg_value) != len(ECDSA_SHA256_OID_TLV) + 2
        ):
            return der

        sig_tag = sig_alg_end
        if sig_tag >= outer_end or der[sig_tag] != 0x03:
            return der

        sig_length, sig_length_header = _decode_tlv_length(der, sig_tag + 1)
        sig_value_start = sig_tag + 1 + sig_length_header
        sig_end = sig_value_start + sig_length
        if sig_end != outer_end:
            return der

        cri_tlv = der[cri_tag:cri_end]
        normalized_sig_alg = (
            b"\x30"
            + _encode_tlv_length(len(ECDSA_SHA256_OID_TLV))
            + ECDSA_SHA256_OID_TLV
        )
        sig_tlv = der[sig_tag:sig_end]
        new_outer_value = cri_tlv + normalized_sig_alg + sig_tlv
        return b"\x30" + _encode_tlv_length(len(new_outer_value)) + new_outer_value
    except (IndexError, ValueError):
        return der


def _decode_base64(body):
    padding = "=" * (-len(body) % 4)
    try:
        if "-" in body or "_" in body:
            return base64.urlsafe_b64decode(body + padding)
        return base64.b64decode(body + padding)
    except (ValueError, base64.binascii.Error):
        return None


def _encode_base64(body, der):
    was_urlsafe = "-" in body or "_" in body
    had_padding = body.endswith("=")

    if was_urlsafe:
        encoded = base64.urlsafe_b64encode(der).decode("ascii")
    else:
        encoded = base64.b64encode(der).decode("ascii")

    if not had_padding:
        encoded = encoded.rstrip("=")
    return encoded


def normalize_csr_output(output):
    """Normalize the DER CSR body while preserving the body.cose envelope."""
    if not isinstance(output, str) or not output:
        return output

    body, separator, cose = output.partition(".")
    der = _decode_base64(body)
    if der is None:
        return output

    normalized = normalize_ecdsa_csr_der(der)
    if normalized == der:
        return output

    normalized_body = _encode_base64(body, normalized)
    return normalized_body + (separator + cose if separator else "")
