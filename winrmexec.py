import os, sys, re, uuid, logging, time, ssl

from copy import deepcopy
from base64 import b64encode, b64decode
from struct import pack, unpack, error
from random import randbytes, randint
from datetime import datetime, UTC

# pip install xmltodict
import xmltodict

# pip install requests
from requests import Session

from urllib3 import disable_warnings
from urllib3.util import SKIP_HEADER
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(category=InsecureRequestWarning)

# -- impacket: ------------------------------------------------------------------------------------
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import ObjectIdentifier, noValue

from impacket.krb5.asn1 import AP_REQ, AP_REP, TGS_REP, seq_set
from impacket.krb5.asn1 import Authenticator, EncAPRepPart

from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, SEALKEY, SIGNKEY, SEAL, SIGN
from impacket.ntlm import NTLMAuthChallenge, AV_PAIRS, NTLMSSP_AV_CHANNEL_BINDINGS

from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import PrincipalNameType, ApplicationTagNumbers, encodeFlags
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, KerberosError

from impacket.krb5.gssapi import GSSAPI, KRB5_AP_REQ, CheckSumField
from impacket.krb5.gssapi import GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG
from impacket.krb5.gssapi import GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

from Cryptodome.Hash import HMAC, MD5, SHA256
from Cryptodome.Cipher import ARC4

# -- helpers and constants: -----------------------------------------------------------------------
def between(buf, pre, suf):
    off = buf.index(pre) + len(pre)
    buf = buf[off:]
    off = buf.index(suf)
    return buf[:off]

def chunks(xs, n):
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s):
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    else:
        return b64encode(s).decode()

def serialize(obj):
    return xmltodict.unparse(obj, full_document=False).encode()

def deserialize(data):
    return xmltodict.parse(data, strip_whitespace=False)

_utfstr = re.compile(r'_x([0-9a-fA-F]{4})_')
def utfstr(s):
    # chars inside xml strings that have non-printable characters are encoded like this, eg:
    # '\n' would be "_x000A_", etc.. although i don't know how to tell if a charcter was
    # encoded during xml serialization or there was a literal *string* "_x000A_" somewhere
    # to begin with:
    try:
        return _utfstr.sub(lambda m: bytes.fromhex(m.group(1)).decode("utf-16be"), s)
    except:
        return s

zero_uuid = str(uuid.UUID(bytes_le=bytes(16))).upper()

# stolen from https://github.com/skelsec/asyauth/blob/main/asyauth/protocols/kerberos/gssapi.py
# as i could not find anything like this in impacket:
def krb5_mech_indep_token_encode(oid, data):
    oid = encoder.encode(ObjectIdentifier(oid)) # KRB5 - Kerberos 5
    payload = oid + data
    n = len(payload)
    if n < 128:
        size = n.to_bytes(1, byteorder="big")
    else:
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        size = (128 + len(size)).to_bytes(1, "big") + size

    return b"\x60" + size + payload

def krb5_mech_indep_token_decode(data):
    skip = 2 + (data[1] if data[1] < 128 else (data[1] - 128))
    return decoder.decode(data[skip:], asn1Spec=ObjectIdentifier)

# -- soap templates for winrm: --------------------------------------------------------------------
soap_req_tmpl = {
    's:Envelope': {
        '@xmlns:rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
        '@xmlns:s': 'http://www.w3.org/2003/05/soap-envelope',
        '@xmlns:wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
        '@xmlns:wsman': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
        '@xmlns:wsmv': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
        's:Header': {
            'wsa:Action': { '@s:mustUnderstand': 'true', '#text': 'REPLACEME' },
            'wsmv:DataLocale': { '@s:mustUnderstand': 'false', '@xml:lang': 'en-US' },
            'wsman:Locale': { '@s:mustUnderstand': 'false', '@xml:lang': 'en-US' },
            'wsman:MaxEnvelopeSize': { '@s:mustUnderstand': 'true', '#text': '64000' },
            'wsa:MessageID': 'REPLACEME', #f"uuid:{message_id}"
            'wsman:OperationTimeout': 'REPLACEME', # f"PT{timeout}S"
            'wsa:ReplyTo': {
                'wsa:Address': {
                    '@s:mustUnderstand': 'true',
                    '#text': 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
                }
            },
            'wsman:ResourceURI': {
                '@s:mustUnderstand': 'true',
                '#text': 'http://schemas.microsoft.com/powershell/Microsoft.PowerShell'
            },
            'wsmv:SessionId': { '@s:mustUnderstand': 'false', '#text': 'REPLACEME' },
            'wsa:To': 'http://localhost',
            'wsman:OptionSet': {
                '@s:mustUnderstand': 'true',
                #'wsman:Option': { REPLACEME }
            },
            "wsman:SelectorSet" : {
                # REPLACEME
            }
        },
        's:Body': {
            # REPLACEME
        }
    }
}

soap_actions = {
    "create"  : "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
    "delete"  : "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
    "receive" : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
    "command" : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
    "signal"  : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
}

# fill in common fields for soap request:
def soap_req(action, session_id, shell_id=None, timeout=20):
    message_id = str(uuid.uuid4()).upper()
    req = deepcopy(soap_req_tmpl)
    req["s:Envelope"]["s:Header"]["wsa:Action"]["#text"] = soap_actions[action]
    req["s:Envelope"]["s:Header"]["wsa:MessageID"] = "uuid:" + message_id
    req["s:Envelope"]["s:Header"]["wsmv:SessionId"]["#text"] = f"uuid:{session_id}"
    req["s:Envelope"]["s:Header"]["wsman:OperationTimeout"] = f"PT{timeout}S"

    if shell_id:
        req["s:Envelope"]["s:Header"]["wsman:SelectorSet"] = {
            "wsman:Selector" : { "@Name" : "ShellId", "#text" : shell_id }
        }

    return req

# this simplifies the response to only grab the elements i will need:
def soap_rsp(rsp):
    action, body = rsp["s:Envelope"]["s:Header"]["a:Action"], rsp["s:Envelope"]["s:Body"]
    if action.endswith("wsman/fault"):
        fault = body["s:Fault"]
        return {
            "fault"   : action,
            "subcode" : fault.get("s:Code",   {}).get("s:Subcode", {}).get("s:Value") or "",
            "reason"  : fault.get("s:Reason", {}).get("s:Text", {}).get("#text") or "",
            "detail"  : fault.get("s:Detail", {}).get("f:Message") or "",
        }
    elif action.endswith("shell/ReceiveResponse"):
        receive = body["rsp:ReceiveResponse"]
        streams = receive.get("rsp:Stream", [])
        if isinstance(streams, dict): # sometimes there's just one stream
            streams = [ streams ]
        return {
            "receive" : action,
            "streams" : [ b64decode(s.get("#text", "")) for s in streams ],
            "state"   : receive.get("rsp:CommandState", {}).get("@State") or ""
        }
    elif action.endswith("transfer/CreateResponse"):
        return { "create" : action }
    elif action.endswith("shell/SignalResponse"):
        return { "signal" : action }
    elif action.endswith("transfer/DeleteResponse"):
        return { "delete" : action }
    elif action.endswith("shell/CommandResponse"):
        return { "command" : action }
    else:
        return { "unknown" : action, "debug" : rsp } # for debugging


# -- PSObjects: -----------------------------------------------------------------------------------
# bare minimum to create relevant ps remoting objects:
ps_nil  = lambda n    : { "Nil"     : { "@N" : n } }
ps_int  = lambda n, v : { "I32"     : { "@N" : n, "#text" : str(v) } }
ps_str  = lambda n, v : { "S"       : { "@N" : n, "#text" : v } }
ps_ver  = lambda n, v : { "Version" : { "@N" : n, "#text" : v } }
ps_bool = lambda n, v : { "B"       : { "@N" : n, "#text" : str(bool(v)).lower()} }
ps_obj  = lambda n, v : { "Obj"     : { "@N" : n, "MS" : v } }
ps_enum = lambda n, v : { "Obj"     : { "@N" : n, "I32" : v } }
ps_smap = lambda elms : { "Obj"     : { "MS" : elms } }

ps_list = lambda name, kind, elements : {
    "Obj" : {
        "@N" : name,
        "LST" : { kind : [ el[kind] for el in elements ] }
    }
}

ps_session_capability = ps_smap([
    ps_ver("protocolversion", "2.3"),
    ps_ver("PSVersion", "2.0"),
    ps_ver("SerializationVersion", "1.1.0.10")
])

ps_host_info = ps_obj("HostInfo", [
    ps_bool("_isHostNull",      True),
    ps_bool("_isHostUINull",    True),
    ps_bool("_isHostRawUINull", True),
    ps_bool("_useRunspaceHost", True)
])

ps_runspace_pool = ps_smap([
    ps_int("MinRunspaces", 1),
    ps_int("MaxRunspaces", 1),
    ps_enum("PSThreadOptions", 0),
    ps_enum("ApartmentState",  2),
    ps_host_info,
    ps_nil("ApplicationArguments")
])

ps_args = lambda args: [
    ps_smap([ ps_str("N", k), ps_str("V", v) if v else ps_nil("V") ]) for k, v in args.items()
]

ps_command = lambda cmd, args : ps_smap([
    ps_str("Cmd", cmd),
    ps_list("Args", "Obj", ps_args(args)),
    ps_bool("IsScript", False),
    ps_nil("UseLocalScope"),
    ps_enum("MergeMyResult", 0),
    ps_enum("MergeToResult", 0),
    ps_enum("MergePreviousResults", 0),
    ps_enum("MergeError", 0),
    ps_enum("MergeWarning", 0),
    ps_enum("MergeVerbose", 0),
    ps_enum("MergeDebug", 0),
    ps_enum("MergeInformation", 0),
])

ps_create_pipeline = lambda commands : ps_smap([
    ps_bool("NoInput", True),
    ps_bool("AddToHistory", False),
    ps_bool("IsNested", False),
    ps_enum("ApartmentState", 2),
    ps_enum("RemoteStreamOptions", 15),
    ps_host_info,
    ps_obj("PowerShell", [
        ps_bool("IsNested", False),
        ps_bool("RedirectShellErrorOutputPipe", False),
        ps_nil("ExtraCmds"),
        ps_nil("History"),
        ps_list("Cmds", "Obj", [ ps_command(cmd, args) for cmd, args in commands ])
    ])
])


# -- message framing: -----------------------------------------------------------------------------
msg_ids = {
    0x00010002 : "SESSION_CAPABILITY",
    0x00010004 : "INIT_RUNSPACEPOOL",
    0x00010005 : "PUBLIC_KEY",
    0x00010006 : "ENCRYPTED_SESSION_KEY",
    0x00010007 : "PUBLIC_KEY_REQUEST",
    0x00010008 : "CONNECT_RUNSPACEPOOL",
    0x0002100B : "RUNSPACEPOOL_INIT_DATA",
    0x0002100C : "RESET_RUNSPACE_STATE",
    0x00021002 : "SET_MAX_RUNSPACES",
    0x00021003 : "SET_MIN_RUNSPACES",
    0x00021004 : "RUNSPACE_AVAILABILITY",
    0x00021005 : "RUNSPACEPOOL_STATE",
    0x00021006 : "CREATE_PIPELINE",
    0x00021007 : "GET_AVAILABLE_RUNSPACES",
    0x00021008 : "USER_EVENT",
    0x00021009 : "APPLICATION_PRIVATE_DATA",
    0x0002100A : "GET_COMMAND_METADATA",
    0x00021100 : "RUNSPACEPOOL_HOST_CALL",
    0x00021101 : "RUNSPACEPOOL_HOST_RESPONSE",
    0x00041002 : "PIPELINE_INPUT",
    0x00041003 : "END_OF_PIPELINE_INPUT",
    0x00041004 : "PIPELINE_OUTPUT",
    0x00041005 : "ERROR_RECORD",
    0x00041006 : "PIPELINE_STATE",
    0x00041007 : "DEBUG_RECORD",
    0x00041008 : "VERBOSE_RECORD",
    0x00041009 : "WARNING_RECORD",
    0x00041010 : "PROGRESS_RECORD",
    0x00041011 : "INFORMATION_RECORD",
    0x00041100 : "PIPELINE_HOST_CALL",
    0x00041101 : "PIPELINE_HOST_RESPONSE"
}

for k, v in msg_ids.items():
    globals()[v] = k

def fragment(next_obj_id, messages):
    # this doesn't do proper fragmentation over multiple wxf:Send requests, but my
    # thinking here is that i'm *sending* only smallish messages, so i can get away
    # with it; defragment() does it properly because server responses can get very large:
    fragments = b""

    for msg_type, rpid, pid, data in messages:
        this  = pack("<I", 0x00002)          # destination = SERVER
        this += pack("<I", msg_type)
        this += uuid.UUID(rpid).bytes_le
        this += uuid.UUID(pid).bytes_le
        this += data

        fragments += pack(">Q", next_obj_id) # object_id
        fragments += pack(">Q", 0)           # fragment_id
        fragments += pack(">B", 0x1 | 0x2)   # pray message fits in this fragment
        fragments += pack(">I", len(this))
        fragments += this

        next_obj_id += 1

    return fragments

def defragment(streams, object_buffer):
    for buf in streams:
        fragments = []
        while buf:
            object_id, fragment_seq = unpack(">QQ", buf[:16])
            is_start, is_end = bool(buf[16] & 1), bool(buf[16] & 2)
            msg_len, = unpack(">I", buf[17:21])
            partial = buf[21:21 + msg_len]
            buf = buf[21 + msg_len:]

            this = object_buffer.get(object_id)
            if this is None:
                this = { "seq" : fragment_seq, "data" : b"" }
                object_buffer[object_id] = this

            if is_start and is_end:
                fragments.append(partial)
                del object_buffer[object_id]
            elif is_start:
                this["data"] = partial
                this["seq"] += 1
            elif is_end:
                fragments.append(this["data"] + partial)
                del object_buffer[object_id]
            else:
                this["data"] += partial
                this["seq"]  += 1

        for frag in fragments:
            _, msg_type = unpack("<II", frag[:8])
            rpid = str(uuid.UUID(bytes_le=frag[8:24])).upper()
            pid  = str(uuid.UUID(bytes_le=frag[24:40])).upper()
            msg  = deserialize(frag[40:].decode())
            yield (msg_type, msg, rpid, pid)

# -- transports: ----------------------------------------------------------------------------------
class BasicTransport:
    def __init__(self, url, username, password):
        self.session = Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER
        self.url  = url
        self.auth = (username, password)

    def send(self, req):
        rsp = self.session.post(self.url, auth=self.auth, data=req, headers={
            "Content-Type" : "application/soap+xml;charset=UTF-8"
        })
        return rsp.content

class NTLMTransport:
    def __init__(self, url, username, password="", nt_hash=""):
        self.url      = url
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash
        self.ssl = urlparse(url).scheme == "https"
        self.session  = None

        if self.ssl:
            cert = ssl.get_server_certificate((urlparse(url).hostname, urlparse(url).port or 443))
            cert = cert.removeprefix("-----BEGIN CERTIFICATE-----\n")
            cert = cert.removesuffix("-----END CERTIFICATE-----\n")
            cert = SHA256.new(b64decode(cert)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()

    def send(self, req):
        if self.session is None:
            self._auth()

        rsp = self._send(req)
        if rsp.status_code == 401:
            logging.debug("server asked to reauth")
            self._auth()
            rsp = self._send(req)

        if rsp.status_code == 401:
            raise RuntimeError("failed to reauth")

        if rsp.status_code not in (200, 500):
            raise RuntimeError("unexcpected response")

        return rsp.content

    def _send(self, req):
        prefix   = b"Content-Type: application/octet-stream\r\n"
        suffix   = b"--Encrypted Boundary--\r\n"
        protocol = "application/HTTP-SPNEGO-session-encrypted"

        seq = pack("<I", self.msgseq)
        enc = self.rc4_cli.encrypt(req)
        sig = HMAC.new(self.key_cli, seq + req, digestmod=MD5).digest()[:8]
        sig = pack("<I", 1) + self.rc4_cli.encrypt(sig) + seq

        data  = b"--Encrypted Boundary\r\n"
        data += f"Content-Type: {protocol}\r\n".encode()
        data += f"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(req)}\r\n".encode()
        data += b"--Encrypted Boundary\r\n"
        data += prefix + pack("<I", len(sig)) + sig + enc + suffix

        rsp = self.session.post(self.url, data=data, headers={
            "Content-Type" : f'multipart/encrypted;protocol="{protocol}";boundary="Encrypted Boundary"'
        })

        if rsp.status_code not in (200, 500):
            return rsp

        try:
            assert b"application/soap+xml;charset=UTF-8" in rsp.content
            body = between(rsp.content, prefix, suffix)
            assert unpack("<II", body[:8]) == (16, 1) # length, version
            assert body[16:20] == seq                 # message sequence
        except:
            raise RuntimeError("failed to parse response")

        plaintext = self.rc4_srv.decrypt(body[20:])

        sig0 = body[8:16]
        sig1 = HMAC.new(self.key_srv, seq + plaintext, digestmod=MD5).digest()[:8]
        sig1 = self.rc4_srv.decrypt(sig1)

        if sig0 != sig1:
            raise RuntimeError("failed to verify response signature")

        self.msgseq += 1
        rsp.headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
        rsp.headers["Content-Length"] = str(len(plaintext))
        rsp._content = plaintext
        return rsp

    def _auth(self, url=None):
        session = Session()
        session.verify = False
        session.headers["User-Agent"] = SKIP_HEADER
        session.headers["Accept-Encoding"] = SKIP_HEADER

        type1 = getNTLMSSPType1()
        type1["flags"] = 0xe0088237 # wiresharked
        type1_token = "Negotiate " + b64str(type1.getData())

        rsp = session.post(self.url, headers={ "Authorization" : type1_token })

        www_auth = rsp.headers.get("WWW-Authenticate", "")
        if not www_auth.startswith("Negotiate "):
            raise RuntimeError("NTLM auth failed")

        type2 = b64decode(www_auth.removeprefix("Negotiate "))

        # include tls channel bindings in case CbtHardeningLevel=Strict
        if self.ssl:
            chal = NTLMAuthChallenge(type2)
            info = AV_PAIRS(chal['TargetInfoFields'])
            info[NTLMSSP_AV_CHANNEL_BINDINGS] = self.gss_bindings
            chal["TargetInfoFields"]          = info.getData()
            chal["TargetInfoFields_len"]      = len(info.getData())
            chal["TargetInfoFields_max_len"]  = len(info.getData())
            type2 = chal.getData()

        nt_hash = bytes.fromhex(self.nt_hash) if self.nt_hash else ""
        type3, key = getNTLMSSPType3(type1, type2, self.username, self.password, "", "", nt_hash)

        type3_token = "Negotiate " + b64str(type3.getData())
        rsp = session.post(self.url, headers= { "Authorization" : type3_token })

        flags = type3["flags"]

        self.session = session
        self.msgseq  = 0
        self.key_cli = SIGNKEY(flags, key, "Client")
        self.key_srv = SIGNKEY(flags, key, "Server")
        self.rc4_cli = ARC4.new(SEALKEY(flags, key, "Client"))
        self.rc4_srv = ARC4.new(SEALKEY(flags, key, "Server"))


class KerberosTransport:
    def __init__(self, url, dc_ip, spn, domain, username, password="", nt_hash="", aes_key=""):
        self.url      = url
        self.ssl      = urlparse(url).scheme == "https"
        self.domain   = domain
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash
        self.aes_key  = aes_key
        self.session  = None

        user = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)
        http = Principal(spn,      type=PrincipalNameType.NT_PRINCIPAL.value)

        tgt, tgs = None, None

        if os.getenv("KRB5CCNAME"):
            _, _, tgt, tgs = CCache.parseFile(target=spn)
            if tgt and not tgs:
                cipher = tgt['cipher']
                tgtkey = tgt['sessionKey']
                tgt    = tgt['KDC_REP']
            elif tgs:
                cipher = tgs['cipher']
                tgskey = tgs['sessionKey']
                tgs    = tgs['KDC_REP']
        else:
            logging.info(f"requesting TGT for {domain}\\{username}")
            tgt, cipher, _, tgtkey = getKerberosTGT(user, password, domain, "", nt_hash, aes_key, dc_ip)

        if not tgt and not tgs:
            raise KerberosError("Could not get TGT or TGS")

        if not tgs:
            logging.info(f"requesting TGS for {spn}")
            tgs, cipher, _, tgskey = getKerberosTGS(http, domain, dc_ip, tgt, cipher, tgtkey)

        ticket = Ticket()
        ticket.from_asn1(decoder.decode(tgs, asn1Spec=TGS_REP())[0]["ticket"])

        self.tgs_ticket = ticket
        self.tgs_cipher = cipher
        self.tgs_key    = tgskey

        if self.ssl:
            cert = ssl.get_server_certificate((urlparse(url).hostname, urlparse(url).port or 443))
            cert = cert.removeprefix("-----BEGIN CERTIFICATE-----\n")
            cert = cert.removesuffix("-----END CERTIFICATE-----\n")
            cert = SHA256.new(b64decode(cert)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()

    def send(self, req):
        if self.session is None:
            self._auth()

        rsp = self._send(req)
        if rsp.status_code == 401:
            logging.debug("server asked to reauth")
            self._auth()
            rsp = self._send(req)

        if rsp.status_code == 401:
            raise RuntimeError("failed to reauth")

        if rsp.status_code not in (200, 500):
            raise RuntimeError("unexcpected response")

        return rsp.content

    def _send(self, req):
        gss = GSSAPI(self.cipher)
        r0, r1 = gss.GSS_Wrap(self.subkey, req, self.msgseq)

        prefix   = b"Content-Type: application/octet-stream\r\n"
        suffix   = b"--Encrypted Boundary--\r\n"
        protocol = "application/HTTP-Kerberos-session-encrypted"

        data  = b"--Encrypted Boundary\r\n"
        data += f"Content-Type: {protocol}\r\n".encode()
        data += f"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(req)}\r\n".encode()
        data += b"--Encrypted Boundary\r\n"
        data += prefix + pack("<I", len(r1)) + r1 + r0 + suffix

        rsp = self.session.post(self.url, verify=False, data=data, headers={
            "Content-Type" : f'multipart/encrypted;protocol="{protocol}";boundary="Encrypted Boundary"'
        })

        if rsp.status_code not in (200, 500):
            return rsp

        try:
            assert b"application/soap+xml;charset=UTF-8" in rsp.content
            body = between(rsp.content, prefix, suffix)
        except:
            raise RuntimeError("failed to parse response")

        try:
            hdr_size  = unpack("<I", body[:4])[0]
            hdr_data  = body[4:][:hdr_size]
            enc_data  = body[4:][hdr_size:]
            hdr_data  = bytes(8) + hdr_data # extra bytes are a hack to reuse GSS_Unwrap() for WinRM
            plaintext = gss.GSS_Unwrap(self.subkey, enc_data, self.msgseq, 'accept', True, hdr_data)[0]
        except:
            raise RuntimeError("failed to decrypt response")

        self.msgseq += 1
        rsp.headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
        rsp.headers["Content-Length"] = str(len(plaintext))
        rsp._content = plaintext
        return rsp

    def _auth(self):
        user = Principal(self.username, type=PrincipalNameType.NT_PRINCIPAL.value)

        checksum = CheckSumField()
        checksum['Lgth']   = 16
        checksum['Flags']  = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG
        checksum['Flags'] |= GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG
        # include tls channel binding in case CbtHardeningLevel=Strict
        if self.ssl:
            checksum['Bnd'] = self.gss_bindings

        now = datetime.now(UTC)

        auth = Authenticator()
        seq_set(auth, 'cname', user.components_to_asn1)
        auth['authenticator-vno']  = 5
        auth['crealm']             = self.domain
        auth['cusec']              = now.microsecond
        auth['ctime']              = KerberosTime.to_asn1(now)
        auth['cksum']              = noValue
        auth['cksum']['cksumtype'] = 0x8003
        auth['cksum']['checksum']  = checksum.getData()
        # include a dummy subkey here with enctype=18 so that when in AP_REP when application
        # returns *it's* subkey it will have this enctype too, otherwise it will have
        # the same enctype as tgskey (eg 23) and WinRM can only work with AES:
        auth['subkey'] = noValue
        auth['subkey']['keyvalue'] = randbytes(32)
        auth['subkey']['keytype']  = 18
        enc_auth = self.tgs_cipher.encrypt(self.tgs_key, 11, encoder.encode(auth), None)

        ap_req = AP_REQ()
        ap_req['pvno']       = 5
        ap_req['msg-type']   = int(ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = encodeFlags([2]) # mutual-required
        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = self.tgs_cipher.enctype
        ap_req['authenticator']['cipher'] = enc_auth
        seq_set(ap_req, 'ticket', self.tgs_ticket.to_asn1)

        # -- "Authorization" token for http request: ----------------------------------------------
        token = KRB5_AP_REQ + encoder.encode(ap_req)
        token = krb5_mech_indep_token_encode("1.2.840.113554.1.2.2", token)
        token = "Kerberos " + b64str(token)

        # -- ask for AP_REP via HTTP: -------------------------------------------------------------
        session = Session()
        session.verify = False
        session.headers["User-Agent"] = SKIP_HEADER
        session.headers["Accept-Encoding"] = SKIP_HEADER
        rsp = session.post(self.url, headers={ "Authorization" : token })
        www_auth = rsp.headers.get("WWW-Authenticate", "")

        try:
            assert www_auth.startswith("Kerberos ")
            www_auth = www_auth.removeprefix("Kerberos ")
            krb_blob = krb5_mech_indep_token_decode(b64decode(www_auth))[1]
            ap_rep   = decoder.decode(krb_blob[2:], asn1Spec=AP_REP())[0]
        except:
            raise RuntimeError("Kerberos auth failed")

        ap_rep_enc = self.tgs_cipher.decrypt(self.tgs_key, 12, ap_rep["enc-part"]["cipher"])
        ap_rep_dec = decoder.decode(ap_rep_enc, asn1Spec=EncAPRepPart())[0]
        keydata    = ap_rep_dec["subkey"]["keyvalue"].asOctets()
        keytype    = ap_rep_dec["subkey"]["keytype"]

        self.subkey  = Key(keytype, keydata)
        self.cipher  = _enctype_table[keytype] # 18
        self.session = session
        self.msgseq  = 0


# -- MS-PSRP stuff from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp ------
class Runspace:
    def __init__(self, transport, timeout=5):
        self.transport      = transport
        self.timeout        = timeout
        self.object_buffer  = {}
        self.next_object_id = 1
        self.session_id     = str(uuid.uuid4()).upper()
        self.shell_id       = str(uuid.uuid4()).upper()

        self.current_command_id = None

    def __enter__(self):
        messages = fragment(self.next_object_id, [
            (SESSION_CAPABILITY, self.shell_id, zero_uuid, serialize(ps_session_capability)),
            (INIT_RUNSPACEPOOL,  self.shell_id, zero_uuid, serialize(ps_runspace_pool))
        ])

        req = soap_req("create", self.session_id, timeout=self.timeout)

        req["s:Envelope"]["s:Header"]["wsman:OptionSet"]["wsman:Option"] = {
            "@MustComply" : 'true',
            "@Name"       : "protocolversion",
            "#text"       : "2.3"
        }

        req["s:Envelope"]["s:Body"] = {
            "rsp:Shell" : {
                "@ShellId"          : self.shell_id,
                "rsp:InputStreams"  : "stdin pr",
                "rsp:OutputStreams" : "stdout",
                "creationXml"       : b64str(messages)
            }
        }
        # TODO: maybe deal with responses, but whatever.. doesn't seem to fail ever
        # and if something happens it will error out when trying to create a pipeline
        self._send(req)
        self._receive()
        self._receive()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        req = soap_req("delete", self.session_id, self.shell_id, self.timeout)
        self._send(req)

    def run_command(self, cmd, debug=True):
        command_id = self._create_pipeline(cmd)
        if not command_id:
            yield { "error" : "failed to create pipeline, if this persists just restart the shell" }
            return

        timeouts = 0
        self.current_command_id = command_id
        while True:
            rsp = self._receive(command_id)
            if "fault" in rsp:
                if rsp["subcode"] == "w:TimedOut":
                    timeouts += 1                  # some commands take a while; this is fine, but
                    yield { "timeout" : timeouts } # yield anyway, maybe user wants to interrupt
                    continue
                else:
                    yield { "error" : rsp["reason"] + "\n" + rsp["detail"] }
                    return

            timeouts = 0 # reset timeout counter when we finally get a response
            for msg_type, msg, _, _ in defragment(rsp["streams"], self.object_buffer):
                if msg_type == PIPELINE_OUTPUT: # from Write-Output
                    yield { "stdout" : utfstr(msg.get("S") or "") }

                elif msg_type == ERROR_RECORD: # from Write-Error
                    yield { "error" : utfstr(msg.get("Obj", {}).get("ToString") or "unknown error") }

                elif msg_type == WARNING_RECORD: # from Write-Warning
                    yield { "warn" : utfstr(msg.get("Obj", {}).get("ToString") or "unknown warning") }

                elif msg_type == INFORMATION_RECORD: # from Write-Host
                    props = msg.get("Obj", {}).get("MS", {}).get("Obj", [{}])[0].get("Props", {})
                    text = props.get("S", {}).get("#text") or ""
                    endl = props.get("B", {}).get("#text", "false") == "false"
                    yield { "info" : utfstr(text), "endl" : "\n" if endl else "" }

                elif msg_type == VERBOSE_RECORD: # from Write-Verbose
                    yield { "verbose" : utfstr(msg.get("Obj", {}).get("ToString") or "") }

                elif msg_type == PIPELINE_STATE: # return exceptions as errors:
                    err = msg.get("Obj", {}).get("MS", {}).get("Obj", {})
                    if err.get("@N") == "ExceptionAsErrorRecord":
                        yield { "error" : utfstr(err.get("ToString") or "uknonwn exception") }

                elif msg_type == PROGRESS_RECORD: # from Write-Progress
                    for progress in msg.get("Obj", {}).get("MS", {}).get("S", []):
                        yield { "progress" : progress.get("#text", "") }

                else: # debug strays in case i missed something:
                    logging.debug(f"{msg_ids.get(msg_type)} : {msg_type:x} : {msg}")

            if rsp["state"]:
                break # == CommandState/Done when pipeline finishes

        self.current_command_id = None

    def interrupt(self):
        if not self.current_command_id:
            return
        req = soap_req("signal", self.session_id, self.shell_id, self.timeout)
        req["s:Envelope"]["s:Body"] = {
            "rsp:Signal" : {
                "@CommandId" : self.current_command_id,
                "rsp:Code" : "powershell/signal/crtl_c",
            }
        }
        return self._send(req)

    def _send(self, req):
        rsp = self.transport.send(serialize(req))
        return soap_rsp(deserialize(rsp))

    def _receive(self, command_id=None):
        req = soap_req("receive", self.session_id, self.shell_id, self.timeout)

        req["s:Envelope"]["s:Header"]["wsman:OptionSet"]["wsman:Option"] = {
            "@Name" : "WSMAN_CMDSHELL_OPTION_KEEPALIVE", "#text" : "True"
        }
        stream = { "#text" : "stdout" } | ({ "@CommandId" : command_id} if command_id else {})

        req["s:Envelope"]["s:Body"] = { "rsp:Receive" : { "rsp:DesiredStream" : stream } }

        return self._send(req)

    def _create_pipeline(self, cmd):
        command_id = str(uuid.uuid4()).upper()

        # Invoke-Expression $cmd | Out-String -Stream
        create_pipeline = ps_create_pipeline([
            ("Invoke-Expression", { "Command" : cmd }),
            ("Out-String", { "Stream" : None } )
        ])

        messages = fragment(self.next_object_id, [
            (CREATE_PIPELINE, self.shell_id, command_id, serialize(create_pipeline))
        ])

        req = soap_req("command", self.session_id, self.shell_id, self.timeout)
        req["s:Envelope"]["s:Body"] = {
            "rsp:CommandLine" : {
                "@CommandId" : command_id,
                "rsp:Command" : "",
                "rsp:Arguments" : b64str(messages)
            }
        }
        rsp = self._send(req)

        if "command" in rsp:
            return command_id

# so with Runspace class you can execute commands like this, eg:
# transport = NTLMTransport("http://box.htb:5985/wsman", "username", "password")
# with Runspace(transport) as runspace:
#  for output in runspace.run_command("whoami /all"):
#     print(output)



# the rest of the code here parses impacket-style arguments (in main) and implements a
# simple shell that runs a REPL loop:
from signal import SIGINT, signal, getsignal
from argparse import ArgumentParser
from ipaddress import ip_address

try:
    from prompt_toolkit import prompt, ANSI
    from prompt_toolkit.history import FileHistory
    prompt_toolkit_available = sys.stdout.isatty()
except ModuleNotFoundError:
    print("'prompt_toolkit' not installed, using built-in 'readline'")
    import readline, atexit
    prompt_toolkit_available = False


class CtrlCHandler:
    def __init__(self, max_interrupts=4, timeout=5):
        self.max_interrupts = max_interrupts
        self.timeout = timeout

    def __enter__(self):
        self.interrupted = 0
        self.released = False
        self.original_handler = getsignal(SIGINT)

        def handler(signum, frame):
            self.interrupted += 1
            if self.interrupted > 1:
                n = self.max_interrupts - self.interrupted + 2
                print()
                print(f"Ctrl+C spammed, {n} more will terminate ungracefully.")
                print(f"Try waiting ~{self.timeout} more seconds for a client to get a "\
                        "chance to send the interrupt")

            if self.interrupted > self.max_interrupts:
                self.release()

        signal(SIGINT, handler)
        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal(SIGINT, self.original_handler)
        self.released = True
        return True

class Shell:
    def __init__(self, runspace):
        self.runspace  = runspace
        self.cwd        = ""
        self.need_clear = False

        if prompt_toolkit_available:
            self.prompt_history = FileHistory(".winrmexec_history")

    def repl(self, inputs=None, debug=True):
        if not inputs:
            inputs = self.read_line()
            self.update_cwd()

        for cmd in inputs:
            if not cmd:
                continue
            elif cmd in { "exit", "quit" }:
                return
            else:
                self.run_with_interrupt(cmd, self.write_line)
                self.update_cwd()

    def read_line(self):
        while True:
            try:
                pre = f"\x1b[1m\x1b[33mPS\x1b[0m {self.cwd}> "
                if prompt_toolkit_available:
                    cmd = prompt(ANSI(pre), history=self.prompt_history, enable_history_search=True)
                else:
                    cmd = input(pre)
            except KeyboardInterrupt:
                continue
            except EOFError:
                return
            else:
                yield cmd

    def write_line(self, out):
        clear = "\033[2K\r" if self.need_clear else ""
        self.need_clear = False

        log_msg = b""
        if msg := out.get("stdout"): # from Write-Output
            print(clear + msg, flush=True)

        elif msg := out.get("info"): # from Write-Host
            endl = out.get("endl", "\n")
            print(clear + msg, end=endl, flush=True)

        elif msg := out.get("error"): # from Write-Error and exceptions
            print(clear + "\x1b[31m" + msg + "\x1b[0m", flush=True)

        elif msg := out.get("warn"): # from Write-Warning
            print(clear + "\x1b[33m" + msg + "\x1b[0m", flush=True)

        elif msg := out.get("verbose"): # from Write-Verbose
            print(clear + msg, flush=True)

        elif progress := out.get("progress"): # from Write-Progress
            print(clear + "\x1b[34m" + progress + "\x1b[0m", end="\r", flush=True)
            self.need_clear = True

    def update_cwd(self):
        self.cwd = self.run_sync("Get-Location | Select -Expand Path").strip()

    def run_sync(self, cmd):
        return "\n".join(out.get("stdout") for out in self.runspace.run_command(cmd) if "stdout" in out)

    def run_with_interrupt(self, cmd, output_handler=None, exception_handler=None):
        output_stream = self.runspace.run_command(cmd)
        while True:
            with CtrlCHandler(timeout=5) as h:
                try:
                    out = next(output_stream)
                except StopIteration:
                    break
                except Exception as e:
                    if exception_handler and exception_handler(e):
                        continue
                    else:
                        raise e

                if output_handler:
                    output_handler(out)

                if h.interrupted:
                    self.runspace.interrupt()

        return h.interrupted > 0


def main():
    """
# NTLM Examples:
  $ winrmexec.py 'box.htb/username:password@dc.box.htb'
  $ winrmexec.py 'username:password@dc.box.htb'
  $ winrmexec.py -hashes 'LM:NT' 'username@dc.box.htb'
  $ winrmexec.py -hashes ':NT' 'username@dc.box.htb'

If password/hashes are not specified, it will prompt for password:
  $ winrmexec.py username@dc.box.htb

If '-target-ip' is specified, target will be ignored (still needs '@' after user[:pass])
  $ winrmexec.py -target-ip '10.10.11.xx' 'username:password@whatever'
  $ winrmexec.py -target-ip '10.10.11.xx' 'username:password@'

If '-target-ip' is not specified, then target-ip=target

If '-ssl' is specified, it will use 5986 port and https:
  $ winrmexec.py -ssl 'username:password@dc01.box.htb'

If '-port' is specified, it will use that instead of 5985. If 'ssl' is also specified it will use https:
  $ winrmexec.py -ssl -port 8443 'username:password@dc01.box.htb'

If '-url' is specified, target, target-ip and port will be ignored:
  $ winrmexec.py -url 'http://dc.box.htb:8888/endpoint' 'username:password@whatever'

If '-url' is not specified it will be constructed as http(s)://target_ip:port/wsman

# Kerberos Examples:
  $ winrmexec.py -k 'box.htb/username:password@dc.box.htb'
  $ winrmexec.py -k -hashes 'LM:NT' 'box.htb/username@dc.box.htb'
  $ winrmexec.py -k -aesKey 'AESHEX' 'box.htb/username@dc.box.htb'

If KRB5CCACHE is in env, it will use domain and username from there:
  $ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass 'dc.box.htb'

It doesn't hurt if you also specify domain/username, but they will be ignored:
  $ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass 'box.htb/username@dc.box.htb'

If target does not resolve to ip, you have to specify target-ip:
  $ winrmexec.py -k -no-pass -target-ip '10.10.11.xx' 'box.htb/username:password@DC'
  $ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass -target-ip '10.10.11.xx' DC

For Kerbros auth it is important that target is a host or FQDN, as it will be used
to construct SPN as HTTP/{target}@{domain}.

Or you can specify '-spn' yourself, in which case target will be ignored (or used only as target-ip):
  $ winrmexec.py -k -spn 'http/dc' 'box.htb/username:password@dc.box.htb'
  $ winrmexec.py -k -target-ip '10.10.11.xx' -spn 'http/dc' box.htb/username:password@whatever
  $ KRB5CCNAME=ticket.ccache winrmexec.py -k -no-pass -target-ip '10.10.11.xx' -spn 'http/dc' 'whatever'

If you have a TGS for SPN other than HTTP (for example CIFS) it still works (at least from what i tried)
If you have a TGT, then it will request TGS for HTTP/{target}@{domain} (or whatever was in your '-spn')

If '-dc-ip' is not specified then dc-ip=domain
For '-url' / '-port' / '-ssl' same rules apply as for NTLM

# Basic Auth Examples (not likely to be enabled):
Same as for NTLM except hashes are not supported:
  # winrmexec.py -basic username:password@dc.box.htb
  # winrmexec.py -basic -target-ip '10.10.11.xx' 'username:password@whatever'
  # winrmexec.py -basic -target-ip '10.10.11.xx' -ssl 'username:password@whatever'
  # winrmexec.py -basic -url 'http://10.10.11.xx/endpoint' 'username:password@whatever'
"""

    print(version.BANNER)
    parser = ArgumentParser()

    parser.add_argument("target", help="[[domain/]username[:password]@]<target>")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-examples', action='store_true', help='Show examples')

    # -- connection params: -----------------------------------------------------------------------
    group = parser.add_argument_group('connection')
    group.add_argument("-dc-ip", default="",
        help="IP Address of the domain controller. If omitted it will use the "\
             "domain part (FQDN) specified in the target parameter")

    group.add_argument("-target-ip", default="",
        help="IP Address of the target machine. If ommited it will use whatever "\
              "was specified as target. This is useful when target is the NetBIOS"\
              "name and you cannot resolve it")

    group.add_argument("-port", default="",
        help="Destination port to connect to WinRM http server, default is 5985")

    group.add_argument("-ssl", action="store_true", help="Use HTTPS")

    group.add_argument("-basic", action="store_true", help="Use Basic auth")

    group.add_argument("-url", default="",
        help="Exact WSMan endpoint, eg. http://host:port/custom_wsman. "\
             "Otherwise it will be constructed as http(s)://target_ip:port/wsman")

    # -- authentication params: -------------------------------------------------------------------
    group = parser.add_argument_group('authentication')
    group.add_argument("-spn", default="", help="Specify exactly the SPN to request for TGS")

    group.add_argument("-hashes", default="", metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH")

    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")

    group.add_argument("-k", action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)"\
             "based on target parameters. If valid credentials cannot be found, it will "\
             "use the ones specified in the command line")

    group.add_argument('-aesKey', metavar = "HEXKEY", default="",
        help="AES key to use for Kerberos Authentication")

    # -- shell params: ----------------------------------------------------------------------------
    parser.add_argument("-X", default="", metavar="COMMAND",
        help="Command to execute, if ommited it will spawn a janky interactive shell")

    parser.add_argument("-timeout", default="5", metavar="SEC", help="Timeout for requests to /wsman")


    args = parser.parse_args()

    if args.examples:
        print(main.__doc__)
        exit()

    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, targetName = parse_target(args.target)

    if args.aesKey and not args.k:
        logging.info("'-aesKey' key specified, using kerberos")
        args.k = True

    aes_key = args.aesKey
    nt_hash = args.hashes.split(':')[1] if ':' in args.hashes else ""
    has_creds = password or nt_hash or aes_key

    if username and not (has_creds or args.no_pass):
        from getpass import getpass
        password = getpass("Password:")
        has_creds = True

    if not args.target_ip and not args.url:
        target_ip = targetName
        logging.info(f"'-target_ip' not specified, using {targetName}")
    else:
        target_ip = args.target_ip

    if not args.port:
        port = 5986 if args.ssl else 5985
        logging.info(f"'-port' not specified, using {port}")
    else:
        port = args.port

    if not args.url:
        if args.ssl:
            url = f"https://{target_ip}:{port}/wsman"
        else:
            url = f"http://{target_ip}:{port}/wsman"
        logging.info(f"'-url' not specified, using {url}")
    else:
        url = args.url

    if args.k:
        if os.getenv("KRB5CCNAME"): # use domain/username from ccache
            domain, username, _, _ = CCache.parseFile()
            logging.info(f"using domain and username from ccache: {domain}\\{username}")
        elif not domain or not username or not has_creds:
            logging.fatal("Need domain, username and one of password/nthash/aes for kerberos auth")
            exit()
        if not args.spn:
            try:
                ip_address(targetName)
                logging.error(f"when using kerberos and '-spn' is not specified, 'targetName' must be FQDN")
                exit()
            except ValueError:
                pass

        if not args.dc_ip:
            logging.info(f"'-dc-ip' not specified, using {domain}")
            dc_ip = domain
        else:
            dc_ip = args.dc_ip

        if not args.spn:
            spn = args.spn or f"HTTP/{targetName}@{domain}"
            logging.info(f"'-spn' not specified, using {spn}")
        else:
            spn = args.spn

        transport = KerberosTransport(url, dc_ip, spn, domain, username, password, nt_hash, aes_key)

    elif args.basic:
        if not username or not password:
            logging.fatal(f"Need username and password for basic auth")
            exit()
        transport = BasicTransport(url, username, password)

    else:
        if not username or not (password or nt_hash):
            logging.fatal(f"Need username and password or hashes for ntlm auth")
            exit()
        transport = NTLMTransport(url, username, password, nt_hash)

    timeout = int(args.timeout)

    with Runspace(transport, timeout) as runspace:
        shell = Shell(runspace)
        try:
            if args.X:
                shell.repl(iter([args.X]))
            else:
                shell.repl()
        except EOFError:
            pass

if __name__ == "__main__":
    main()

