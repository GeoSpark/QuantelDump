import unittest
from decrypt_password import descramble_password, smush_bits
from encrypt_password import scramble_password, desmush_bits, create_checksum_characters


class QPasswordTest(unittest.TestCase):
    PASSWORDS = (
        (10000, 'VVUE2QDXV3RQQW6TRQ'),  # Option 13063 Expiry 0
        (13464, '2DMWG37TM37N5PAKXS'),  # Option 46 Expiry 15/01/96
        (13464, '7VLVYM6T634JVNS5WY'),  # Option 66 Expiry 03/07/95
        (10866, 'GX9EZKC4DTGSM5ZYNV')  # Font 10064
    )

    def test_scrambling(self):
        # Descramble/scramble should be commutative
        for password in self.PASSWORDS:
            descrambled = descramble_password(password)
            scrambled = scramble_password(descrambled)
            print(password[1], descrambled, scrambled)
            self.assertEqual(scrambled, password[1])

    def test_smush(self):
        # Smushing should be commutative
        for password in self.PASSWORDS:
            # decrypt
            descrambled_password = descramble_password(password)
            checksum, smushed_bits = smush_bits(descrambled_password)

            # encrypt
            checksum2, descrambled2 = desmush_bits(smushed_bits)
            descrambled2.extend(create_checksum_characters(checksum2))

            # debug
            print("CS: ", checksum, checksum2, " -- PW: ", descrambled_password, ''.join(descrambled2))
            self.assertEqual(checksum, checksum2)
            self.assertEqual(descrambled_password, ''.join(descrambled2))


if __name__ == '__main__':
    unittest.main()
