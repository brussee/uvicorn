import asyncio
import ssl
import urllib.parse

from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple


if TYPE_CHECKING:
    from asgiref.typing import WWWScope


RDNS_MAPPING: Dict[str, str] = {
    "commonName": "CN",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "streetAddress": "STREET",
    "domainComponent": "DC",
    "userId": "UID",
}

TLS_VERSION_MAP: Dict[str, int] = {
    "TLSv1": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}


def get_remote_addr(transport: asyncio.Transport) -> Optional[Tuple[str, int]]:
    socket_info = transport.get_extra_info("socket")
    if socket_info is not None:
        try:
            info = socket_info.getpeername()
            return (str(info[0]), int(info[1])) if isinstance(info, tuple) else None
        except OSError:
            # This case appears to inconsistently occur with uvloop
            # bound to a unix domain socket.
            return None

    info = transport.get_extra_info("peername")
    if info is not None and isinstance(info, (list, tuple)) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def get_local_addr(transport: asyncio.Transport) -> Optional[Tuple[str, int]]:
    socket_info = transport.get_extra_info("socket")
    if socket_info is not None:
        info = socket_info.getsockname()

        return (str(info[0]), int(info[1])) if isinstance(info, tuple) else None
    info = transport.get_extra_info("sockname")
    if info is not None and isinstance(info, (list, tuple)) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def is_ssl(transport: asyncio.Transport) -> bool:
    return bool(transport.get_extra_info("sslcontext"))


def get_client_addr(scope: WWWScope) -> str:
    client = scope.get("client")
    if not client:
        return ""
    return "%s:%d" % client


def get_path_with_query_string(scope: WWWScope) -> str:
    path_with_query_string = urllib.parse.quote(scope["path"])
    if scope["query_string"]:
        path_with_query_string = "{}?{}".format(
            path_with_query_string, scope["query_string"].decode("ascii")
        )
    return path_with_query_string


def get_tls_info(transport: asyncio.Transport) -> Optional[Dict]:

    ###
    # server_cert: Unable to set from transport information
    # client_cert_chain: Just the peercert, currently no access to the full cert chain
    # client_cert_name:
    # client_cert_error: No access to this
    # tls_version:
    # cipher_suite: Too hard to convert without direct access to openssl
    ###

    ssl_info: Dict[str, Any] = {
        "server_cert": None,
        "client_cert_chain": [],
        "client_cert_name": None,
        "client_cert_error": None,
        "tls_version": None,
        "cipher_suite": None,
    }

    ssl_object = transport.get_extra_info("ssl_object", default=None)
    peercert = ssl_object.getpeercert()

    if peercert:
        rdn_strings = []
        for rdn in peercert["subject"]:
            rdn_strings.append(
                "+".join(
                    [
                        "%s = %s" % (RDNS_MAPPING[entry[0]], entry[1])
                        for entry in reversed(rdn)
                        if entry[0] in RDNS_MAPPING
                    ]
                )
            )

        ssl_info["client_cert_chain"] = [
            ssl.DER_cert_to_PEM_cert(ssl_object.getpeercert(binary_form=True))
        ]
        ssl_info["client_cert_name"] = ", ".join(rdn_strings) if rdn_strings else ""
        ssl_info["tls_version"] = (
            TLS_VERSION_MAP[ssl_object.version()]
            if ssl_object.version() in TLS_VERSION_MAP
            else None
        )
        ssl_info["cipher_suite"] = list(ssl_object.cipher())

        return ssl_info

    return None
