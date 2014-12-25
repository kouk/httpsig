#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import mock
import unittest

import httpsig.sign as sign
from httpsig.utils import parse_authorization_header


sign.DEFAULT_SIGN_ALGORITHM = "rsa-sha256"


class TestSign(unittest.TestCase):

    def setUp(self):
        self.key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        self.key = open(self.key_path, 'rb').read()

    def test_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key)
        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=')

    def test_all(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'content-md5',
            'content-length'
        ])
        unsigned = {
            'Host': 'example.com',
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method='POST', path='/foo?param=value&pet=dog')

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['headers'], '(request-target) host date content-type content-md5 content-length')
        self.assertEqual(params['signature'], 'G8/Uh6BBDaqldRi3VfFfklHSFoq8CMt5NUZiepq0q66e+fS3Up3BmXn0NbUnr3L1WgAAZGplifRAJqp2LgeZ5gXNk6UX9zV3hw5BERLWscWXlwX/dvHQES27lGRCvyFv3djHP6Plfd5mhPWRkmjnvqeOOSS0lZJYFYHJz994s6w=')


class TestHMACSHA1(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.hmac import HMACSHA1
        self.test_class = HMACSHA1
        self.test_secret = b'secret'
        self.test_data = 'Message'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'hmac')
        self.assertEquals(self.test_class.hash_name, 'sha1')

    def test_value(self):
        test_obj = self.test_class(self.test_secret)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'gPQlziBEGEZE+Fq7plW/qziLdqc='
        )


class TestHMACSHA256(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.hmac import HMACSHA256
        self.test_class = HMACSHA256
        self.test_secret = b'secret'
        self.test_data = 'Message'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'hmac')
        self.assertEquals(self.test_class.hash_name, 'sha256')

    def test_value(self):
        test_obj = self.test_class(self.test_secret)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'qnR8UCqJggD55PohusaBNviGoOJ67HC6Btry4qXLVZc=',
        )


class TestHMACSHA512(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.hmac import HMACSHA512
        self.test_class = HMACSHA512
        self.test_secret = b'secret'
        self.test_data = 'Message'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'hmac')
        self.assertEquals(self.test_class.hash_name, 'sha512')

    def test_value(self):
        test_obj = self.test_class(self.test_secret)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'z12KOCXYQjCZyKf6WP+yYBONCS+IwNuv9oPbRcL4u+WetE4BvAm1Ysy+bEyGxq/' + \
            'QDLAufO0sPnVLUl/ubvPGdQ=='
        )


class TestRSASHA1(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.rsa import RSASHA1
        self.test_class = RSASHA1
        self.test_data = 'Message'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'rsa')
        self.assertEquals(self.test_class.hash_name, 'sha1')

    def test_value(self):
        key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        key = open(key_path, 'rb').read()
        test_obj = self.test_class(key)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'hBQDzQoGiaH+jdOGU/bIr8uhXiQPSn3qJFzssx8qVwdn+d' + \
            'czeOgLMo7yo4i+gvVNT38CSsDy1v68jqLV78CMKfAD7CfZ' + \
            'wnPTjsjAmuC9a72XWkTul8s2m7KYB7CfaugSgkBTdgaw/u' + \
            'WTvnDSt1ebSklOHjEB1+Ye6nRsoxQIqFM='
        )


class TestRSASHA256(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.rsa import RSASHA256
        self.test_class = RSASHA256
        self.test_data = '(request-target): post /foo?param=value&pet=dog\n' + \
            'host: example.com\n' + \
            'date: Thu, 05 Jan 2012 21:31:40 GMT\n' + \
            'content-type: application/json\n' + \
            'content-md5: Sd/dVLAcvNLSq16eXua5uQ==\ncontent-length: 18'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'rsa')
        self.assertEquals(self.test_class.hash_name, 'sha256')

    def test_value(self):
        key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        key = open(key_path, 'rb').read()
        test_obj = self.test_class(key)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'G8/Uh6BBDaqldRi3VfFfklHSFoq8CMt5NUZiepq0q66e+fS3Up3BmXn0NbUnr3L' + \
            '1WgAAZGplifRAJqp2LgeZ5gXNk6UX9zV3hw5BERLWscWXlwX/dvHQES27lGRCvy' + \
            'Fv3djHP6Plfd5mhPWRkmjnvqeOOSS0lZJYFYHJz994s6w='
        )


class TestRSASHA512(unittest.TestCase):
    def setUp(self):
        from httpsig.algorithms.rsa import RSASHA512
        self.test_class = RSASHA512
        self.test_data = 'Message'

    def tearDown(self):
        self.test_class = None

    def test_meta(self):
        self.assertEquals(self.test_class.algorithm_name, 'rsa')
        self.assertEquals(self.test_class.hash_name, 'sha512')

    def test_value(self):
        key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        key = open(key_path, 'rb').read()
        test_obj = self.test_class(key)
        self.assertEquals(
            test_obj.create_signature(self.test_data),
            'a9kYzF/IDzPQbYPvl92m5Cd40PCMUXMpg09IdLcS3Cfy1ZAeGBo5ZqNrJEqqdYS' + \
            'Py9CJKJTIJLcWjdhXmyIDKH7Wo4dlcs15eOK2YuX10+RO5eJwNT8OXS83iQ3Xs7' + \
            'U4W8hKe5EXKTzCdPH4HF3pV2SQsteYhoukMGcv6Bf71to='
        )
