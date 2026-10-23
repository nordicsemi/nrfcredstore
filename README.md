# nrfcredstore


[![PyPI version](https://img.shields.io/pypi/v/nrfcredstore)](https://pypi.org/project/nrfcredstore/)
![License](https://img.shields.io/pypi/l/nrfcredstore)
![Python versions](https://img.shields.io/pypi/pyversions/nrfcredstore)

nrfcredstore is a command line tool that simplifies managing credentials stored in Nordic Semiconductor modems, like the [nRF9151](https://www.nordicsemi.com/Products/nRF9151). The typical use case of nrfcredstore is to automate the provisioning of cloud certificates that are stored securely in the modem.

## Install

Run the following command to use this package as a dependency:

    pip3 install nrfcredstore

## Requirements

The device must be able to respond to AT commands. The [Cellular: AT Client sample](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/at_client/README.html) can be used, and the [nRF9151 DK application and modem firmware](https://www.nordicsemi.com/Products/Development-hardware/nRF9151-DK/Download?lang=en#infotabs) download contains a pre-built firmware.

For a device without a modem, such as nRF71 Series SoCs and the nRF53 or nRF54 Series SoCs hosting the nRF70 Series Wi-Fi companion ICs, use the `--cmd-type tls-shell` option. The device must be built with the Zephyr TLS credentials shell (`CONFIG_TLS_CREDENTIALS_SHELL`) and, to generate a key, with `CONFIG_TLS_CREDENTIALS_KEYGEN`.

## Command Line Interface

```
usage: nrfcredstore [-h] [--baudrate BAUDRATE] [--timeout TIMEOUT] [--debug] [--cmd-type {at,shell,tls-shell,auto}]
                    dev {list,write,delete,deleteall,imei,attoken,generate} ...

Manage certificates stored in a cellular modem.

positional arguments:
  dev                   Device used to communicate with the modem. For interactive selection of serial port, use "auto". For RTT, use "rtt". If given a SEGGER
                        serial number, it is assumed to be an RTT device.

options:
  -h, --help            show this help message and exit
  --baudrate BAUDRATE   Serial baudrate
  --timeout TIMEOUT     Serial communication timeout in seconds
  --debug               Enable debug logging
  --cmd-type {at,shell,tls-shell,auto}
                        Command type to use. "at" for AT commands, "shell" for AT commands in a shell, "tls-shell" for the Zephyr TLS credentials
                        shell commands of a device without a modem (supports write, delete and generate only), "auto" to detect automatically
                        between "at" and "shell".

subcommands:
  {list,write,delete,deleteall,imei,attoken,generate}
                        Certificate related commands
    list                List all keys stored in the modem
    write               Write key/cert to a secure tag
    delete              Delete value from a secure tag
    deleteall           Delete all keys in a secure tag
    imei                Get IMEI from the modem
    attoken             Get attestation token of the modem
    generate            Generate private key
```

### list subcommand

List keys stored in the modem.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev list [--tag SECURE_TAG [--type KEY_TYPE]]
```

#### example

```
$ nrfcredstore /dev/tty.usbmodem0009600000001 list --tag 123
Secure tag   Key type           SHA
123          ROOT_CA_CERT       XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
123          CLIENT_CERT        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
123          CLIENT_KEY         XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### write subcommand

Write key/cert to a security tag. KEY_TYPE must be either ROOT_CA_CERT, CLIENT_CERT, CLIENT_KEY, or PSK.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev write SECURE_TAG KEY_TYPE FILENAME
```

#### example

    $ nrfcredstore /dev/tty.usbmodem0009600000001 write 123 ROOT_CA_CERT root-ca.pem

### delete subcommand

Delete value from a security tag.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev delete SECURE_TAG KEY_TYPE
```

#### example

    $ nrfcredstore /dev/tty.usbmodem0009600000001 delete 123 ROOT_CA_CERT

### deleteall subcommand

Delete all writable security tags.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev deleteall
```

### imei subcommand

Read IMEI from modem.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev imei
```

### attoken subcommand

Read Attestation Token from modem.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev attoken
```


### generate subcommand

> [!IMPORTANT]
> This command requires modem firmware version 1.3.0 or later.

Generate a private key in the modem and output a certificate signing request.

```
usage: nrfcredstore [--baudrate BAUDRATE] [--timeout TIMEOUT] dev generate SECURE_TAG FILENAME
```

#### example

    $ nrfcredstore /dev/tty.usbmodem0009600000001 generate 123 device_cert.der

    # Convert DER to CSR
    $ openssl req -pubkey -in device_cert.der -inform DER > device_cert.csr

#### Device without a modem

With `--cmd-type tls-shell`, the private key and the CSR are generated on the device with the key generation commands of the TLS credentials shell (`cred keygen` and `cred csr`). The private key never leaves the device. The CSR subject is required and is set with the `--attributes` option. The shell has no default subject, so choose the common name (CN) that the cloud service expects, for example the device ID.

    $ nrfcredstore /dev/ttyACM0 --cmd-type tls-shell generate 123 device_cert.der --attributes "CN=my-device"

    # Convert the DER CSR to PEM
    $ openssl req -inform DER -in device_cert.der -outform PEM -out device_cert.csr.pem

After the CSR is signed, install the certificate and the CA certificate with the `write` subcommand.

    $ nrfcredstore /dev/ttyACM0 --cmd-type tls-shell write 123 CLIENT_CERT device_cert.pem
    $ nrfcredstore /dev/ttyACM0 --cmd-type tls-shell write 123 ROOT_CA_CERT ca.pem

## Development installation

For development mode, you need [poetry](https://python-poetry.org/):

    curl -sSL https://install.python-poetry.org | python3 -

Install package dependencies, development dependencies, and the nrfcredstore itself into poetry's internal virtual environment:

    poetry install

## Test

Running the tests depends on a [development installation](#development-installation).

    poetry run pytest

Check coverage

    poetry run pytest --cov=src tests --cov-report=html
