from __future__ import absolute_import

"""M2Crypto PGP2.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from M2Crypto.PGP.RSA import new_pub_key
from M2Crypto.PGP.packet import public_key_packet  # noqa
from M2Crypto.PGP.constants import *  # noqa
from M2Crypto.PGP.packet import *  # noqa


class PublicKey:
    def __init__(self, pubkey_pkt):
        # type: (public_key_packet) -> None
        import warnings
        warnings.warn(
            'Deprecated. No maintainer for PGP. If you use this, ' +
            'please inform M2Crypto maintainer.',
            DeprecationWarning)

        self._pubkey_pkt = pubkey_pkt
        self._pubkey = new_pub_key((pubkey_pkt._e, pubkey_pkt._n))
        self._userid = {}  # type: dict
        self._signature = {}  # type: dict

    def keyid(self):
        # type: () -> bytes
        return self._pubkey.n[-8:]

    def add_userid(self, u_pkt):
        # type: (packet.userid_packet) -> None
        assert isinstance(u_pkt, packet.userid_packet)
        self._userid[u_pkt.userid()] = u_pkt

    def remove_userid(self, userid):
        # type: (int) -> None
        del self._userid[userid]

    def add_signature(self, userid, s_pkt):
        # type: (int, signature_packet) -> None
        assert isinstance(s_pkt, signature_packet)
        assert userid in self._userid
        if userid in self._signature:
            self._signature.append(s_pkt)
        else:
            self._signature = [s_pkt]

    def __getitem__(self, id):
        # type: (int) -> signature_packet
        return self._userid[id]

    def __setitem__(self, *args):
        raise NotImplementedError

    def __delitem__(self, id):
        # type: (int) -> None
        del self._userid[id]
        if self._signature[id]:
            del self._signature[id]

    def write(self, stream):
        pass

    def encrypt(self, ptxt):
        # XXX Munge ptxt into pgp format.
        return self._pubkey.public_encrypt(ptxt, RSA.pkcs1_padding)

    def decrypt(self, ctxt):
        # XXX Munge ctxt into pgp format.
        return self._pubkey.public_encrypt(ctxt, RSA.pkcs1_padding)
