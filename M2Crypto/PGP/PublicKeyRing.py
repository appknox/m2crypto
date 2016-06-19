from __future__ import absolute_import

"""M2Crypto PGP2.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from M2Crypto import util
from M2Crypto.PGP.PublicKey import *  # noqa
from M2Crypto.PGP.constants import *  # noqa
from M2Crypto.PGP.packet import *  # noqa
if util.py27plus:
    from typing import Tuple  # noqa


class PublicKeyRing:
    def __init__(self, keyring):
        # type: (object) -> None
        import warnings
        warnings.warn(
            'Deprecated. No maintainer for PGP. If you use this, ' +
            'please inform M2Crypto maintainer.',
            DeprecationWarning)

        self._keyring = keyring
        self._userid = {}
        self._keyid = {}
        self._spurious = []
        self._pubkey = []

    def load(self):
        # type: () -> None
        curr_pub = None
        curr_index = -1

        ps = packet.packet_stream(self._keyring)
        while 1:
            pkt = ps.read()

            if pkt is None:
                break

            elif isinstance(pkt, packet.public_key_packet):
                curr_index = curr_index + 1
                curr_pub = PublicKey.PublicKey(pkt)
                self._pubkey.append(curr_pub)
                # self._keyid[curr_pub.keyid()] = (curr_pub, curr_index)

            elif isinstance(pkt, packet.userid_packet):
                if curr_pub is None:
                    self._spurious.append(pkt)
                else:
                    curr_pub.add_userid(pkt)
                    self._userid[pkt.userid()] = (curr_pub, curr_index)

            elif isinstance(pkt, packet.signature_packet):
                if curr_pub is None:
                    self._spurious.append(pkt)
                else:
                    curr_pub.add_signature(pkt)

            else:
                self._spurious.append(pkt)

        ps.close()

    def __getitem__(self, id):
        # type: (int) -> int
        return self._userid[id][0]

    def __setitem__(self, *args):
        # type: (*list) -> None
        raise NotImplementedError

    def __delitem__(self, id):
        # type: (int) -> None
        pkt, idx = self._userid[id]
        del self._pubkey[idx]
        del self._userid[idx]
        pkt, idx = self._keyid[id]
        del self._keyid[idx]

    def spurious(self):
        # type: () -> Tuple[packet.signature_packet]
        return tuple(self._spurious)

    def save(self, keyring):
        # type: (file) -> None
        for p in self._pubkey:
            pp = p.pack()
            keyring.write(pp)


def load_pubring(filename='pubring.pgp'):
    # type: (str) -> PublicKeyRing
    pkr = PublicKeyRing(open(filename, 'rb'))
    pkr.load()
    return pkr
