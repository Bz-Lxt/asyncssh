# Copyright (c) 2015-2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for matching against known_hosts file"""

import binascii
import hashlib
import hmac
import os
import sys

import asyncssh

from asyncssh.known_hosts import KnownHostsCommandStage, SSHKnownHostsCommand
from .util import AsyncTestCase, TempDirTestCase, asynctest
from .util import get_test_key, x509_available

if x509_available: # pragma: no branch
    from asyncssh.crypto import X509NamePattern


def _hash(host):
    """Return a hashed version of a hostname in a known_hosts file"""

    salt = os.urandom(20)
    hosthash = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    entry = b'|'.join((b'', b'1', binascii.b2a_base64(salt)[:-1],
                       binascii.b2a_base64(hosthash)[:-1]))

    return entry.decode()


class _TestKnownHosts(TempDirTestCase):
    """Unit tests for known_hosts module"""

    keylists = ([], [], [], [], [], [], [])
    imported_keylists = ([], [], [], [], [], [], [])

    @classmethod
    def setUpClass(cls):
        """Create public keys needed for test"""

        super().setUpClass()

        for keylist, imported_keylist in zip(cls.keylists[:3],
                                             cls.imported_keylists[:3]):
            for i in range(3):
                key = get_test_key('ssh-rsa', i)
                keylist.append(key.export_public_key().decode('ascii'))
                imported_keylist.append(key.convert_to_public())

        if x509_available: # pragma: no branch
            for keylist, imported_keylist in zip(cls.keylists[3:5],
                                                 cls.imported_keylists[3:5]):
                for i in range(3, 5):
                    key = get_test_key('ssh-rsa', i)
                    cert = key.generate_x509_user_certificate(key, 'OU=user',
                                                              'OU=user')
                    keylist.append(
                        cert.export_certificate('openssh').decode('ascii'))
                    imported_keylist.append(cert)

            for keylist, imported_keylist in zip(cls.keylists[5:],
                                                 cls.imported_keylists[5:]):
                for name in ('OU=user', 'OU=revoked'):
                    keylist.append('x509v3-ssh-rsa subject=' + name + '\n')
                    imported_keylist.append(X509NamePattern(name))

    def check_match(self, known_hosts, results=None, host='host',
                    addr='1.2.3.4', port=22):
        """Check the result of calling match_known_hosts"""

        if results:
            results = tuple([kl[r] for r in result]
                            for kl, result in zip(self.imported_keylists,
                                                  results))

        matches = asyncssh.match_known_hosts(known_hosts, host, addr, port)
        self.assertEqual(matches, results)

    def check_hosts(self, patlists, results=None, host='host', addr='1.2.3.4',
                    port=22, from_file=False, from_bytes=False,
                    as_callable=False, as_tuple=False):
        """Check a known_hosts file built from the specified patterns"""

        def call_match(host, addr, port):
            """Test passing callable as known_hosts"""

            return asyncssh.match_known_hosts(_known_hosts, host, addr, port)

        prefixes = ('', '@cert-authority ', '@revoked ',
                    '', '@revoked ', '', '@revoked ')
        known_hosts = '# Comment line\n   # Comment line with whitespace\n\n'

        for prefix, patlist, keys in zip(prefixes, patlists, self.keylists):
            for pattern, key in zip(patlist, keys):
                known_hosts += f'{prefix}{pattern} {key}'

        if from_file:
            with open('known_hosts', 'w') as f:
                f.write(known_hosts)

            known_hosts = 'known_hosts'
        elif from_bytes:
            known_hosts = known_hosts.encode()
        elif as_callable:
            _known_hosts = asyncssh.import_known_hosts(known_hosts)
            known_hosts = call_match
        elif as_tuple:
            known_hosts = asyncssh.import_known_hosts(known_hosts)
            known_hosts = asyncssh.match_known_hosts(known_hosts, host,
                                                     addr, port)
        else:
            known_hosts = asyncssh.import_known_hosts(known_hosts)

        return self.check_match(known_hosts, results, host, addr, port)

    def test_match(self):
        """Test known host matching"""

        matches = (
            ('Empty file', ([], [], [], [], [], [], []),
             ([], [], [], [], [], [], [])),
            ('Exact host and port', (['[host]:22'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Exact host', (['host'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Exact host CA', ([], ['host'], [], [], [], [], []),
             ([], [0], [], [], [], [], [])),
            ('Exact host revoked', ([], [], ['host'], [], [], [], []),
             ([], [], [0], [], [], [], [])),
            ('Multiple exact', (['host'], ['host'], [], [], [], [], []),
             ([0], [0], [], [], [], [], [])),
            ('Wildcard host', (['hos*'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Mismatched port', (['[host]:23'], [], [], [], [], [], []),
             ([], [], [], [], [], [], [])),
            ('Negative host', (['hos*,!host'], [], [], [], [], [], []),
             ([], [], [], [], [], [], [])),
            ('Exact addr and port', (['[1.2.3.4]:22'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Exact addr', (['1.2.3.4'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Subnet', (['1.2.3.0/24'], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Negative addr', (['1.2.3.0/24,!1.2.3.4', [], [], []], [], [], []),
             ([], [], [], [], [], [], [])),
            ('Hashed host', ([_hash('host')], [], [], [], [], [], []),
             ([0], [], [], [], [], [], [])),
            ('Hashed addr', ([_hash('1.2.3.4')], [], [], [], [], [], []),
             ([0], [], [], [], [], [], []))
        )

        if x509_available: # pragma: no branch
            matches += (
                ('Exact host X.509', ([], [], [], ['host'], [], [], []),
                 ([], [], [], [0], [], [], [])),
                ('Exact host X.509 revoked', ([], [], [], [], ['host'], [], []),
                 ([], [], [], [], [0], [], [])),
                ('Exact host subject', ([], [], [], [], [], ['host'], []),
                 ([], [], [], [], [], [0], [])),
                ('Exact host revoked subject',
                 ([], [], [], [], [], [], ['host']),
                 ([], [], [], [], [], [], [0])),
            )

        for testname, patlists, result in matches:
            with self.subTest(testname):
                self.check_hosts(patlists, result)

    def test_no_addr(self):
        """Test match without providing addr"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), addr='')
        self.check_hosts((['1.2.3.4'], [], [], [], [], [], []),
                         ([], [], [], [], [], [], []), addr='')

    def test_no_port(self):
        """Test match without providing port"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), port=None)
        self.check_hosts((['[host]:22'], [], [], [], [], [], []),
                         ([], [], [], [], [], [], []), port=None)

    def test_no_match(self):
        """Test for cases where no match is found"""

        no_match = (([], [], [], [], [], [], []),
                    (['host1', 'host2'], [], [], [], [], [], []),
                    (['2.3.4.5', '3.4.5.6'], [], [], [], [], [], []),
                    (['[host]:2222', '[host]:22222'], [], [], [], [], [], []))

        for patlists in no_match:
            self.check_hosts(patlists, ([], [], [], [], [], [], []))

    def test_scoped_addr(self):
        """Test match on scoped addresses"""

        self.check_hosts((['fe80::1%1'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), addr='fe80::1%1')
        self.check_hosts((['fe80::%1/64'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), addr='fe80::1%1')
        self.check_hosts((['fe80::1%2'], [], [], [], [], [], []),
                         ([], [], [], [], [], [], []), addr='fe80::1%1')
        self.check_hosts((['2001:2::%3/64'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), addr='2001:2::1')

    def test_missing_key(self):
        """Test for line with missing key data"""

        with self.assertRaises(ValueError):
            self.check_match(b'xxx\n')

    def test_missing_key_with_tag(self):
        """Test for line with tag with missing key data"""

        with self.assertRaises(ValueError):
            self.check_match(b'@cert-authority xxx\n')

    def test_invalid_key(self):
        """Test for line with invalid key"""

        self.check_match(b'xxx yyy\n', ([], [], [], [], [], [], []))

    def test_invalid_marker(self):
        """Test for line with invalid marker"""

        with self.assertRaises(ValueError):
            self.check_match(b'@xxx yyy zzz\n')

    def test_incomplete_hash(self):
        """Test for line with incomplete host hash"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|1|aaaa'], [], [], [], [], [], [], [], []))

    def test_invalid_hash(self):
        """Test for line with invalid host hash"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|1|aaa'], [], [], [], [], [], [], [], []))

    def test_unknown_hash_type(self):
        """Test for line with unknown host hash type"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|2|aaaa|'], [], [], [], [], [], [], [], []))

    def test_file(self):
        """Test match against file"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), from_file=True)

    def test_bytes(self):
        """Test match against byte string"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), from_bytes=True)

    def test_callable(self):
        """Test match using callable"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), as_callable=True)

    def test_tuple(self):
        """Test passing already constructed tuple of keys"""

        self.check_hosts((['host'], [], [], [], [], [], []),
                         ([0], [], [], [], [], [], []), as_tuple=True)


class _TestKnownHostsCommand(AsyncTestCase):
    """Unit tests for KnownHostsCommand execution"""

    def setUp(self):
        super().setUp()

        if os.path.exists('khc_args.log'):
            os.remove('khc_args.log')

        self._tokens = {'%': '%', 'C': 'conn-hash', 'd': os.path.expanduser('~'),
                        'h': 'host', 'i': '0', 'j': '', 'k': 'host',
                        'L': 'localhost', 'l': 'localhost.local',
                        'n': 'host', 'p': '22', 'r': 'user', 'u': 'user'}

        self._script = os.path.join(os.getcwd(), 'khc_command.py')

        with open(self._script, 'w') as f:
            f.write(
                'import sys\n'
                'with open("khc_args.log", "a") as log:\n'
                '    log.write("|".join(sys.argv[1:]) + "\\n")\n'
                'sys.stdout.write(open("khc_output").read())\n')

        self._fail_script = os.path.join(os.getcwd(), 'khc_fail.py')

        with open(self._fail_script, 'w') as f:
            f.write('import sys\nsys.exit(1)\n')

        key = get_test_key('ssh-rsa')
        self._publine = key.export_public_key().decode('ascii').strip()
        self._key = key.convert_to_public()

        with open('khc_output', 'w') as f:
            f.write(f'host {self._publine}\n')

    def _command(self, template):
        return SSHKnownHostsCommand(template, self._tokens)

    @asynctest
    async def test_stages_and_connection_tokens(self):
        """Test command invocation stages and connection token expansion"""

        command = self._command(
            f'{sys.executable} {self._script} %I %H %h %p %t %f %K')

        await command.run(KnownHostsCommandStage.ORDER, 'host')
        await command.run(KnownHostsCommandStage.HOSTNAME, 'host')
        await command.run(KnownHostsCommandStage.ADDRESS, '1.2.3.4')

        with open('khc_args.log') as f:
            calls = [line.strip().split('|') for line in f]

        self.assertEqual(calls, [
            ['ORDER', 'host', 'host', '22', 'NONE', 'NONE', 'NONE'],
            ['HOSTNAME', 'host', 'host', '22', 'NONE', 'NONE', 'NONE'],
            ['ADDRESS', '1.2.3.4', 'host', '22', 'NONE', 'NONE', 'NONE']])

    @asynctest
    async def test_key_tokens(self):
        """Test expansion of host key tokens with an offered key"""

        command = self._command(
            f'{sys.executable} {self._script} %I %t %f %K')

        await command.run(KnownHostsCommandStage.HOSTNAME, 'host', self._key)

        with open('khc_args.log') as f:
            stage, key_type, fingerprint, key_b64 = \
                f.read().strip().split('|')

        self.assertEqual(stage, 'HOSTNAME')
        self.assertEqual(key_type, str(self._key.algorithm, 'ascii'))
        self.assertEqual(fingerprint, self._key.get_fingerprint())
        self.assertEqual(key_b64,
                         binascii.b2a_base64(
                             self._key.public_data)[:-1].decode('ascii'))

    @asynctest
    async def test_output_matches_known_host(self):
        """Test host keys returned by a command are matched like a file"""

        command = self._command(f'{sys.executable} {self._script} %I')

        known_hosts = await command.run(KnownHostsCommandStage.ORDER, 'host')

        matches = asyncssh.match_known_hosts(known_hosts, 'host', '', None)
        self.assertEqual(matches[0], [self._key])

    @asynctest
    async def test_quoted_arguments(self):
        """Test that quoted arguments are preserved"""

        command = self._command(
            f'{sys.executable} {self._script} %I "quoted arg"')

        await command.run(KnownHostsCommandStage.ORDER, 'host')

        with open('khc_args.log') as f:
            args = f.read().strip().split('|')

        self.assertEqual(args, ['ORDER', 'quoted arg'])

    @asynctest
    async def test_nonzero_exit(self):
        """Test that a non-zero exit status raises an error"""

        command = self._command(f'{sys.executable} {self._fail_script} %I')

        with self.assertRaises(ValueError):
            await command.run(KnownHostsCommandStage.HOSTNAME, 'host')

    @asynctest
    async def test_missing_executable(self):
        """Test that a missing executable raises an error"""

        command = self._command('khc_no_such_command %I')

        with self.assertRaises(ValueError):
            await command.run(KnownHostsCommandStage.HOSTNAME, 'host')

    @asynctest
    async def test_invalid_token(self):
        """Test that an unknown percent token raises an error"""

        command = self._command(
            f'{sys.executable} {self._script} %Z')

        with self.assertRaises(ValueError):
            await command.run(KnownHostsCommandStage.HOSTNAME, 'host')

    @asynctest
    async def test_no_arguments(self):
        """Test that an empty command raises an error"""

        with self.assertRaises(ValueError):
            await SSHKnownHostsCommand('', self._tokens).run(
                KnownHostsCommandStage.HOSTNAME, 'host')
