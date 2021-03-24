from datetime import date
import unittest
from password import unshuffle_password, smush_bits, shuffle_password, desmush_bits, create_checksum_characters, PaintboxOption


class QPasswordTest(unittest.TestCase):
    PASSWORDS = (
        PaintboxOption('VVUE2QDXV3RQQW6TRQ', 10000, 13063, 0, None),
        PaintboxOption('2DMWG37TM37N5PAKXS', 13464, 46, 0, date(1996, 1, 15)),
        PaintboxOption('7VLVYM6T634JVNS5WY', 13464, 66, 0, date(1995, 7, 3))
    )

    def test_shuffling(self):
        # Unshuffle/shuffle should be commutative
        for password in self.PASSWORDS:
            unshuffled = unshuffle_password(password.password)
            shuffled = shuffle_password(unshuffled)
            print(password.password, unshuffled, shuffled)
            self.assertEqual(shuffled, password.password)

    def test_smush(self):
        # Smushing should be commutative
        for password in self.PASSWORDS:
            # decrypt
            unshuffled_password = unshuffle_password(password.password)
            checksum, smushed_bits = smush_bits(unshuffled_password)

            # encrypt
            checksum2, unshuffled = desmush_bits(smushed_bits)
            unshuffled += create_checksum_characters(checksum2)

            # debug
            print("CS: ", checksum, checksum2, " -- PW: ", unshuffled_password, unshuffled)
            self.assertEqual(checksum, checksum2)
            self.assertEqual(unshuffled_password, unshuffled)


if __name__ == '__main__':
    unittest.main()
