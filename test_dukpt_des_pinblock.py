from unittest import TestCase, main

from Crypto.Cipher import DES, DES3

from dukpt_des_pinblock import DukptDesPinBlock, CommandLine


class DukptDesPinBlockDocumentationCase(TestCase):
    def test_constructor(self):
        bdk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        ksn_10_bytes = bytes.fromhex("ffff9876543210e00000")
        ksn_08_bytes = bytes.fromhex("9876543210e00000")
        # always use 10b ksn (event when 8b version is given)
        self.assertEqual(ksn_10_bytes, DukptDesPinBlock(bdk, ksn_08_bytes)._ksn)
        self.assertEqual(ksn_10_bytes, DukptDesPinBlock(bdk, ksn_10_bytes)._ksn)

    def test_generate_pinblock(self):
        bdk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        pan = "4012345678909"
        pin = "1234"
        previous_ksn = bytes.fromhex("FFFF9876543210EFFC00")
        actual_ksn = bytes.fromhex("FFFF9876543210F00000")
        excepted_pinblock = bytes.fromhex("73EC88AD0AC5830E")
        # with increase ksn before use
        dukpt = DukptDesPinBlock(bdk, previous_ksn)
        pinblock, ksn = dukpt.generate_pinblock(pin, pan)
        self.assertEqual(excepted_pinblock, pinblock)
        self.assertEqual(actual_ksn, ksn)
        # without increase ksn before use
        dukpt = DukptDesPinBlock(bdk, actual_ksn, next_ksn_flag=False)
        pinblock, ksn = dukpt.generate_pinblock(pin, pan)
        self.assertEqual(excepted_pinblock, pinblock)
        self.assertEqual(actual_ksn, ksn)

    def test_generate_pin(self):
        bdk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        pan = "4012345678909"
        excepted_pin = "1234"
        actual_ksn = bytes.fromhex("FFFF9876543210F00000")
        pinblock = bytes.fromhex("73EC88AD0AC5830E")
        # during generate pin we don't increase ksn
        dukpt = DukptDesPinBlock(bdk, actual_ksn)
        self.assertEqual(excepted_pin, dukpt.generate_pin(pinblock, pan))
        # when pinblock can't be translated to pin throw exception
        wrong_pinblock = bytes.fromhex("0000000000000000")
        dukpt = DukptDesPinBlock(bdk, wrong_pinblock)
        self.assertRaises(ValueError, dukpt.generate_pin, wrong_pinblock, pan)

    def test_next_ksn(self):
        bdk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        dukpt = DukptDesPinBlock(bdk, bytes.fromhex("ffff9876543210e00000"))
        self.assertEqual("ffff9876543210e00001", dukpt.next_ksn().hex())
        # ksn counter always should be at most 10 bit count
        dukpt = DukptDesPinBlock(bdk, bytes.fromhex("ffff9876543210e3f0f0"))
        self.assertEqual("ffff9876543210e3f100", dukpt.next_ksn().hex())
        # increase incorrect ksn to proper one (never trust user kind)
        dukpt = DukptDesPinBlock(bdk, bytes.fromhex("ffff9876543210e0ffcf"))
        self.assertEqual("ffff9876543210e10000", dukpt.next_ksn().hex())
        # no left ksn
        dukpt = DukptDesPinBlock(bdk, bytes.fromhex("ffff9876543210fff800"))
        self.assertRaises(ValueError, dukpt.next_ksn)


class CommandLineCase(TestCase):
    def test_encrypt_pinblock_with_next_ksn(self):
        args = CommandLine.encrypt1_example
        self.assertEqual(
            "PINBLOCK: 73EC88AD0AC5830E\nKSN:  FFFF9876543210F00000",
            CommandLine().run(args)
        )

    def test_encrypt_pinblock_without_next_ksn(self):
        args = CommandLine.encrypt2_example
        self.assertEqual(
            "PINBLOCK: 73EC88AD0AC5830E\nKSN:  FFFF9876543210F00000",
            CommandLine().run(args)
        )

    def test_decrypt(self):
        args = CommandLine.decrypt_example
        self.assertEqual("PIN: 1234", CommandLine().run(args))

    def test_next_ksn(self):
        args = CommandLine.next_ksn_example
        self.assertEqual(
            "NEXT KSN: FFFF9876543210F00000",
            CommandLine().run(args)
        )

    def test_no_ksn_left(self):
        args = CommandLine.next_ksn_example
        args[-1] = "ffff9876543210fff800"
        self.assertEqual(
            "KSN can't be increased (exhausted)",
            CommandLine().run(args)
        )

    def test_decrypt_with_wrong_pinblock(self):
        args = CommandLine.decrypt_example
        args[2] = "73EC88AD0AC58300"
        self.assertEqual(
            "Can't decrypt pin (pin part: ecc16c67502f3a28)",
            CommandLine().run(args)
        )


class DukptDesPinBlockInternalCase(TestCase):
    def test_ipek(self):
        dukpt = DukptDesPinBlock(
            bdk=bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
            ksn=bytes.fromhex('FFFF9876543210E00000')
        )
        self.assertEqual('6ac292faa1315b4d858ab3a3d7d5933a',
                         dukpt._generate_ipek().hex())

    def test_generate_pin_key(self):
        dukpt = DukptDesPinBlock(
            bdk=bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
            ksn=bytes.fromhex('FFFF9876543210E00001')
        )
        self.assertEqual('042666b49184cf5c68de9628d0397b36',
                         dukpt._generate_pin_key().hex())

    def test_next_ksn_all(self):
        dukpt = DukptDesPinBlock(
            bdk=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
            ksn=bytes.fromhex("ffff9876543210e00000")
        )
        cnt = 0
        try:
            while dukpt.next_ksn():
                cnt += 1
        except ValueError as _:
            pass
        self.assertEqual("ffff9876543210fff800", dukpt._ksn.hex())
        self.assertEqual(2 ** 20 - 1, cnt)


class DesEdeEcbExternalLibraryCase(TestCase):
    def setUp(self):
        self.key = bytes.fromhex('042666B49184CF5C68DE9628D0397B36')
        self.decrypted = bytes.fromhex('041274EDCBA9876F')
        self.encrypted = bytes.fromhex('1B9C1845EB993A7A')

    def test_encrypt(self):
        encrypted = DES3.new(self.key, DES3.MODE_ECB).encrypt(self.decrypted)
        self.assertEqual(self.encrypted, encrypted)

    def test_decrypt(self):
        decrypted = DES3.new(self.key, DES3.MODE_ECB).decrypt(self.encrypted)
        self.assertEqual(self.decrypted, decrypted)


class DesEcbExternalLibraryCase(TestCase):
    def setUp(self):
        self.key = bytes.fromhex('0123456789ABCDEF')
        self.decrypted = bytes.fromhex('0000000000000000')
        self.encrypted = bytes.fromhex('d5d44ff720683d0d')

    def test_encrypt(self):
        encrypted = DES.new(self.key, DES.MODE_ECB).encrypt(self.decrypted)
        self.assertEqual(self.encrypted, encrypted)

    def test_decrypt(self):
        decrypted = DES.new(self.key, DES.MODE_ECB).decrypt(self.encrypted)
        self.assertEqual(self.decrypted, decrypted)


if __name__ == '__main__':
    main()
