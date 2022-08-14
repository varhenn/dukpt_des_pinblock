#!/usr/bin/env python3.9
"""Dukpt des pin block utility

Specification: ANS X9.24-2004
Layout: Derived unique key per transaction
Cipher: TripleDes (ECB mode) / Des (ECB mode)
PinBlock format: ISO-0 (ISO 9564-1 Format 0)
"""
import logging
from argparse import ArgumentParser, RawTextHelpFormatter, BooleanOptionalAction
from typing import Tuple
from sys import argv

from Crypto.Cipher import DES, DES3  # pycryptodome library

__author__ = 'zaeta'
__licence__ = 'BSD 2-Clause'


def xor(first: bytes, second: bytes) -> bytes:
    assert len(first) == len(second), "xor elements must have the same size"
    return bytes([f ^ s for f, s in zip(first, second)])


class DukptDesPinBlock:
    """Dukpt Des pinblock (ANS X9.24-2004) implementation"""
    _c_mask = bytes.fromhex('C0C0C0C000000000C0C0C0C000000000')
    _pin_mask = bytes.fromhex('00000000000000FF00000000000000FF')

    def __init__(self, bdk: bytes, ksn: bytes, next_ksn_flag: bool = True):
        assert len(bdk) == 16, "Incorrect Bdk"
        assert len(ksn) in {8, 10}, "Incorrect Ksn"
        self._bdk: bytes = bdk
        self._ksn: bytearray = bytearray(ksn)
        self._increase_ksn: bool = next_ksn_flag
        if len(ksn) == 8:
            self._ksn = bytearray(bytes([0xFF, 0xFF]) + self._ksn)
        if bin(self._counter()).count('1') > 10:
            logging.warning("Given KSN doesn't comply with the specification")

    def generate_pinblock(self, pin: str, pan: str) -> Tuple[bytes, bytes]:
        """Generate pinblock with given pin"""
        assert 4 <= len(pin) <= 12 and pin.isdigit(), "Incorrect Pin"
        assert 12 <= len(pan) <= 19 and pan.isdigit(), "Incorrect Pan"
        ksn = self._ksn
        if self._increase_ksn:
            ksn = self.next_ksn()
        pin_part = bytes.fromhex(f"{len(pin):02}{pin}".ljust(16, 'F'))
        pan_part = bytes.fromhex(pan[-min(13, len(pan)):-1].zfill(16))
        clear_pinblock = xor(pin_part, pan_part)
        pin_key = self._generate_pin_key()
        pinblock = DES3.new(pin_key, mode=DES3.MODE_ECB).encrypt(clear_pinblock)
        return pinblock, bytes(ksn)

    def generate_pin(self, pinblock: bytes, pan: str) -> str:
        """Generate pin with given pinblock"""
        assert len(pinblock) == 8, "Incorrect Pinblock"
        assert 12 <= len(pan) <= 19 and pan.isdigit(), "Incorrect Pan"
        pin_key = self._generate_pin_key()
        clear_pinblock = DES3.new(pin_key, mode=DES3.MODE_ECB).decrypt(pinblock)
        pan_part = bytes.fromhex(pan[-min(13, len(pan)):-1].zfill(16))
        pin_part = xor(clear_pinblock, pan_part)
        try:
            pin_len = int(pin_part.hex()[:2])
            return pin_part.hex()[2:pin_len + 2]
        except Exception as _:
            raise ValueError(f"Can't decrypt pin (pin part: {pin_part.hex()})")

    def next_ksn(self) -> bytes:
        """Increase Key Serial Number to next value"""
        counter = self._counter()
        while True:
            step = 1
            if bin(counter).count('1') >= 10:
                while step & counter == 0:
                    step *= 2
            counter += step
            if counter >= 0x200000:
                raise ValueError("KSN can't be increased (exhausted)")
            if bin(counter).count('1') <= 10:
                self._replace_counter(counter)
                return self._ksn

    def _generate_pin_key(self) -> bytes:
        """Generate derived pin key"""
        curkey = self._generate_ipek()
        r8 = self._ksn_with_zeroed_counter()[-8:]
        sr = 0x100000
        r3 = self._counter()
        while sr:
            if (sr & r3) != 0:
                srb = sr.to_bytes(8, byteorder="big")
                r8 = bytes([a | b for a, b in zip(r8, srb)])
                r8a = xor(curkey[8:], r8)
                r8a = DES.new(curkey[:8], mode=DES.MODE_ECB).encrypt(r8a)
                r8a = xor(r8a, curkey[8:])
                curkey = xor(curkey, self._c_mask)
                r8b = xor(curkey[8:], r8)
                r8b = DES.new(curkey[:8], mode=DES.MODE_ECB).encrypt(r8b)
                r8b = xor(curkey[8:], r8b)
                curkey = r8b + r8a
            sr >>= 1
        return xor(curkey, self._pin_mask)

    def _generate_ipek(self) -> bytes:
        """Generate initially loaded pin entry device key"""
        ksnr = self._ksn_with_zeroed_counter()[:8]
        left = DES3.new(self._bdk, DES3.MODE_ECB).encrypt(ksnr)
        right_key = xor(self._bdk, self._c_mask)
        right = DES3.new(right_key, DES3.MODE_ECB).encrypt(ksnr)
        return left + right

    def _counter(self) -> int:
        """Returns 21 bits counter of KSN as integer"""
        first = (self._ksn[-3] & 0x1F) * 0x10000
        return first + self._ksn[-2] * 0x100 + self._ksn[-1]

    def _ksn_with_zeroed_counter(self) -> bytes:
        """Generate ksn with zero filled counter"""
        return bytes([*self._ksn[:-3], self._ksn[-3] & 0xE0, 0x00, 0x00])

    def _replace_counter(self, counter: int) -> None:
        """Replace counter of KSN"""
        tmp = counter.to_bytes(3, byteorder="big")
        self._ksn[-3] = (self._ksn[-3] & 0xE0) | tmp[0]
        self._ksn[-2] = tmp[1]
        self._ksn[-1] = tmp[2]


class CommandLine:
    encrypt1_example = ['encrypt',
                        '--pin', '1234',
                        '--pan', '4012345678909',
                        '--bdk', '0123456789ABCDEFFEDCBA9876543210',
                        '--ksn', 'FFFF9876543210EFFC00']
    encrypt2_example = ['encrypt',
                        '--pin', '1234',
                        '--pan', '4012345678909',
                        '--bdk', '0123456789ABCDEFFEDCBA9876543210',
                        '--ksn', 'FFFF9876543210F00000',
                        '--no-next-ksn']
    decrypt_example = ['decrypt',
                       '--pinblock', '73EC88AD0AC5830E',
                       '--pan', '4012345678909',
                       '--bdk', '0123456789ABCDEFFEDCBA9876543210',
                       '--ksn', 'FFFF9876543210F00000']
    next_ksn_example = ['next-ksn', '--ksn', 'FFFF9876543210EFFC00']

    def __init__(self):
        def ksn_type(ksn: str) -> bytes:
            if len(ksn) not in {16, 20}:
                raise ValueError
            return bytes.fromhex(ksn)

        def bdk_type(bdk: str) -> bytes:
            if len(bdk) != 32:
                raise ValueError
            return bytes.fromhex(bdk)

        def pinblock_type(pinblock: str) -> bytes:
            if len(pinblock) != 16:
                raise ValueError
            return bytes.fromhex(pinblock)

        def pan_type(pan: str) -> str:
            if 12 <= len(pan) <= 19 and pan.isdigit():
                return pan
            raise ValueError

        def pin_type(data: str) -> str:
            if 4 <= len(data) <= 12 and data.isdigit():
                return data
            raise ValueError

        parser = ArgumentParser(
            description="Dukpt DES pinblock encrypt/decrypt utility",
            epilog="Examples:"
                   f"\n  {argv[0]} {' '.join(self.encrypt1_example)}\n"
                   f"\n  {argv[0]} {' '.join(self.encrypt2_example)}\n"
                   f"\n  {argv[0]} {' '.join(self.decrypt_example)}\n"
                   f"\n  {argv[0]} {' '.join(self.next_ksn_example)}\n"
                   "\nWARNING:"
                   "\n  Dukpt DES version is deprecated"
                   "\n  Please use actual version if possible",
            formatter_class=RawTextHelpFormatter
        )
        actions = ['encrypt', 'decrypt', 'next-ksn']
        parser.add_argument('action', metavar='ACTION', choices=actions,
                            help=f"One of {','.join(actions)} action")
        parser.add_argument('--ksn', type=ksn_type, metavar='KSN',
                            required=True,
                            help="Key serial number")
        parser.add_argument('--bdk', type=bdk_type, metavar='BDK',
                            help="Base derivation key")
        parser.add_argument('--pan', type=pan_type, metavar='PAN',
                            help='Payment card number')
        parser.add_argument('--pin', type=pin_type, metavar='PIN',
                            help="Personal identification number")
        parser.add_argument('--pinblock', type=pinblock_type,
                            metavar='PINBLOCK',
                            help="Pin block")
        parser.add_argument('--next-ksn', type=bool,
                            action=BooleanOptionalAction,
                            metavar='next_ksn', default=True, required=False,
                            help="Only used during encrypt action")
        self._parser = parser

    def run(self, args=None) -> str:
        opts = self._parser.parse_args(args)
        bdk = opts.bdk or bytes.fromhex("00000000000000000000000000000000")
        dukpt = DukptDesPinBlock(bdk, opts.ksn, opts.next_ksn)
        try:
            if opts.action == "encrypt":
                pinblock, ksn = dukpt.generate_pinblock(opts.pin, opts.pan)
                return f"PINBLOCK: {pinblock.hex().upper()}\n" \
                       f"KSN:  {ksn.hex().upper()}"
            elif opts.action == "decrypt":
                return f"PIN: {dukpt.generate_pin(opts.pinblock, opts.pan)}"
            elif opts.action == "next-ksn":
                return f"NEXT KSN: {dukpt.next_ksn().hex().upper()}"
        except Exception as exc:
            return str(exc)


if __name__ == "__main__":
    print(CommandLine().run())
