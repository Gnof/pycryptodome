# ===================================================================
#
# Copyright (c) 2014, Legrandin <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================

import os
import re
import unittest
from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import b, tobytes, bchr
from Crypto.Util.strxor import strxor_c
from Crypto.SelfTest.st_common import list_test_cases

from Crypto.Hash import BLAKE2b

def load_test_vectors():

    test_dir, _ = os.path.split(os.path.abspath(__file__))
    test_vector_file = os.path.join(test_dir, "test_vectors",
                                    "BLAKE2b", "blake2b-test.txt")

    expected = "in"
    test_vectors = []
    for line in open(test_vector_file, "rt"):

        if line.strip() == "" or line.startswith("#"):
            continue

        res = re.match("%s:\t([0-9A-Fa-f]*)" % expected, line)
        if not res:
            raise ValueError("Incorrect test vector format (line %d)" % line_number)

        if res.group(1):
            bin_value = unhexlify(tobytes(res.group(1)))
        else:
            bin_value = b("")
        if expected == "in":
            input_data = bin_value
            expected = "key"
        elif expected == "key":
            key = bin_value
            expected = "hash"
        else:
            result = bin_value
            expected = "in"
            test_vectors.append((input_data, key, result))

    return test_vectors


class Blake2bTest(unittest.TestCase):

    def test_new_positive(self):

        h = BLAKE2b.new(digest_bits=512)
        for new_func in BLAKE2b.new, h.new:

            for dbits in xrange(8, 513, 8):
                hobj = new_func(digest_bits=dbits)
                self.assertEqual(hobj.digest_size, dbits // 8)

            for dbytes in xrange (1, 65):
                hobj = new_func(digest_bytes=dbytes)
                self.assertEqual(hobj.digest_size, dbytes)

            digest1 = new_func(data=b("\x90"), digest_bytes=64).digest()
            digest2 = new_func(digest_bytes=64).update(b("\x90")).digest()
            self.assertEqual(digest1, digest2)

            new_func(data=b("A"), key=b("5"), digest_bytes=64)

    def test_new_negative(self):
        self.assertRaises(TypeError, BLAKE2b.new)
        self.assertRaises(TypeError, BLAKE2b.new, digest_bytes=64, digest_bits=512)
        self.assertRaises(ValueError, BLAKE2b.new, digest_bytes=0)
        self.assertRaises(ValueError, BLAKE2b.new, digest_bytes=65)
        self.assertRaises(ValueError, BLAKE2b.new, digest_bits=7)
        self.assertRaises(ValueError, BLAKE2b.new, digest_bits=15)
        self.assertRaises(ValueError, BLAKE2b.new, digest_bits=513)
        self.assertRaises(TypeError, BLAKE2b.new, digest_bytes=64, key=u"string")
        self.assertRaises(TypeError, BLAKE2b.new, digest_bytes=64, data=u"string")

    def test_update(self):
        pieces = [ bchr(10) * 200, bchr(20) * 300 ]
        h = BLAKE2b.new(digest_bytes=64)
        h.update(pieces[0]).update(pieces[1])
        digest = h.digest()
        h = BLAKE2b.new(digest_bytes=64)
        h.update(pieces[0] + pieces[1])
        self.assertEqual(h.digest(), digest)

    def test_update_negative(self):
        h = BLAKE2b.new(digest_bytes=64)
        self.assertRaises(TypeError, h.update, u"string")

    def test_digest(self):
        h = BLAKE2b.new(digest_bytes=64)
        digest = h.digest()

        # hexdigest does not change the state
        self.assertEqual(h.digest(), digest)
        # digest returns a byte string
        self.failUnless(isinstance(digest,  type(b("digest"))))

    def test_hex_digest(self):
        mac = BLAKE2b.new(digest_bits=512)
        digest = mac.digest()
        hexdigest = mac.hexdigest()

        # hexdigest is equivalent to digest
        self.assertEqual(hexlify(digest), tobytes(hexdigest))
        # hexdigest does not change the state
        self.assertEqual(mac.hexdigest(), hexdigest)
        # hexdigest returns a string
        self.failUnless(isinstance(hexdigest, type("digest")))

    def test_copy(self):
        h = BLAKE2b.new(digest_bits=512, data=b("init"))
        h2 = h.copy()
        self.assertEqual(h.digest(), h2.digest())
        h.update(b("second"))
        self.assertNotEqual(h.digest(), h2.digest())
        h2.update(b("second"))
        self.assertEqual(h.digest(), h2.digest())

    def test_verify(self):
        h = BLAKE2b.new(digest_bytes=64, key=b("4"))
        mac = h.digest()
        h.verify(mac)
        wrong_mac = strxor_c(mac, 255)
        self.assertRaises(ValueError, h.verify, wrong_mac)

    def test_hexverify(self):
        h = BLAKE2b.new(digest_bytes=64, key=b("4"))
        mac = h.hexdigest()
        h.hexverify(mac)
        self.assertRaises(ValueError, h.hexverify, "4556")

    def test_official_test_vectors(self):
        tvs = load_test_vectors()
        for (input_data, key, result) in tvs:
            mac = BLAKE2b.new(key=key, digest_bytes=64)
            mac.update(input_data)
            self.assertEqual(mac.digest(), result)

class Blake2bTestVector1(unittest.TestCase):

    def setUp(self):
        test_dir, _ = os.path.split(os.path.abspath(__file__))
        test_vector_file = os.path.join(test_dir, "test_vectors",
                                        "BLAKE2b", "tv1.txt")

        self.test_vectors = []
        for line in open(test_vector_file, "rt"):
            if line.strip() == "" or line.startswith("#"):
                continue
            res = re.match("digest: ([0-9A-Fa-f]*)", line)
            if not res:
                raise ValueError("Incorrect test vector format (line %d)" % line_number)

            self.test_vectors.append(unhexlify(tobytes(res.group(1))))

    def runTest(self):

        for tv in self.test_vectors:
            digest_bytes = len(tv)
            next_data = b("")
            for _ in xrange(100):
                h = BLAKE2b.new(digest_bytes=digest_bytes)
                h.update(next_data)
                next_data = h.digest() + next_data
            self.assertEqual(h.digest(), tv)

class Blake2bTestVector2(unittest.TestCase):

    def setUp(self):
        test_dir, _ = os.path.split(os.path.abspath(__file__))
        test_vector_file = os.path.join(test_dir, "test_vectors",
                                        "BLAKE2b", "tv2.txt")

        self.test_vectors = []
        for line in open(test_vector_file, "rt"):
            if line.strip() == "" or line.startswith("#"):
                continue
            res = re.match("digest\(([0-9]+)\): ([0-9A-Fa-f]*)", line)
            if not res:
                raise ValueError("Incorrect test vector format (line %d)" % line_number)

            key_size = int(res.group(1))
            result = unhexlify(tobytes(res.group(2)))
            self.test_vectors.append((key_size, result))

    def runTest(self):

        for key_size, result in self.test_vectors:
            next_data = b("")
            for _ in xrange(100):
                h = BLAKE2b.new(digest_bytes=64, key=b("A" * key_size))
                h.update(next_data)
                next_data = h.digest() + next_data
            self.assertEqual(h.digest(), result)


def get_tests(config={}):
    tests = list_test_cases(Blake2bTest)
    tests.append(Blake2bTestVector1())
    tests.append(Blake2bTestVector2())
    return tests


if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
