import ast
import copy
import pathlib
import unittest

from parsers.anytls import parse, to_uri
from parsers.clash2base64 import clash2v2ray

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AnyTLSConversionTests(unittest.TestCase):
    def proxy(self, **updates):
        proxy = {
            'name': '日本 AnyTLS 测试', 'type': 'anytls',
            'server': 'proxy.example.com', 'port': 443, 'password': 'test-password',
            'sni': 'tls.example.com', 'client-fingerprint': 'chrome',
            'alpn': ['h2', 'http/1.1'], 'skip-cert-verify': False,
            'idle-session-check-interval': 30, 'idle-session-timeout': 30,
            'min-idle-session': 0, 'udp': True,
        }
        proxy.update(updates)
        return proxy

    def test_clash_round_trip(self):
        proxy = self.proxy()
        original = copy.deepcopy(proxy)
        node = parse(clash2v2ray(proxy))
        self.assertEqual(proxy, original)
        self.assertEqual(node['type'], 'anytls')
        self.assertEqual(node['tag'], proxy['name'])
        self.assertEqual(node['server'], proxy['server'])
        self.assertEqual(node['server_port'], 443)
        self.assertEqual(node['password'], proxy['password'])
        self.assertEqual(node['tls'], {
            'enabled': True, 'insecure': False, 'server_name': 'tls.example.com',
            'alpn': ['h2', 'http/1.1'],
            'utls': {'enabled': True, 'fingerprint': 'chrome'},
        })
        self.assertEqual(node['idle_session_check_interval'], '30s')
        self.assertEqual(node['idle_session_timeout'], '30s')
        self.assertEqual(node['min_idle_session'], 0)

    def test_reserved_password_characters(self):
        for password in ('a@b:c/?#=&+%', '中文🔑+ test', 'ends=='):
            with self.subTest(password=password):
                self.assertEqual(parse(to_uri(self.proxy(password=password)))['password'], password)

    def test_ipv6_endpoint(self):
        node = parse(to_uri(self.proxy(server='2001:db8::1', port=8443)))
        self.assertEqual(node['server'], '2001:db8::1')
        self.assertEqual(node['server_port'], 8443)

    def test_secure_by_default(self):
        proxy = self.proxy()
        del proxy['skip-cert-verify']
        self.assertFalse(parse(to_uri(proxy))['tls']['insecure'])
        self.assertFalse(parse('anytls://test@proxy.example.com:443')['tls']['insecure'])

    def test_explicit_verification_setting(self):
        for value, expected in ((True, True), ('true', True), ('1', True),
                                (False, False), ('false', False), (None, False)):
            with self.subTest(value=value):
                self.assertEqual(parse(to_uri(self.proxy(**{'skip-cert-verify': value})))['tls']['insecure'], expected)

    def test_optional_fields_and_duration_units(self):
        node = parse(to_uri(self.proxy(**{
            'idle-session-check-interval': '500ms', 'idle-session-timeout': '2m',
            'min-idle-session': 2, 'client-metadata': 'test metadata',
            'sni': '', 'client-fingerprint': '', 'alpn': [],
        })))
        self.assertEqual(node['idle_session_check_interval'], '500ms')
        self.assertEqual(node['idle_session_timeout'], '2m')
        self.assertEqual(node['min_idle_session'], 2)
        self.assertEqual(node['client_metadata'], 'test metadata')
        self.assertEqual(node['tls'], {'enabled': True, 'insecure': False})

    def test_bad_links_are_rejected(self):
        for link in ('anytls://missing-password', 'anytls://p@host',
                     'anytls://p@host:0', 'anytls://p@host:65536',
                     'anytls://p@host:443?min-idle-session=-1',
                     'anytls://p@host:443?idle-session-timeout=-1',
                     'anytls://p@host:443?idle-session-timeout=NaN'):
            with self.subTest(link=link), self.assertRaises(ValueError):
                parse(link)

    def test_existing_shadowsocks_still_converts(self):
        uri = clash2v2ray({'name': 'SS regression', 'type': 'ss', 'server': 'ss.example.com',
                          'port': 8388, 'cipher': 'aes-128-gcm', 'password': 'example'})
        self.assertTrue(uri.startswith('ss://'))
        self.assertTrue(uri.endswith('#SS%20regression'))

    def test_bad_node_does_not_duplicate_previous_node(self):
        module = ast.parse((ROOT / 'main.py').read_text(encoding='utf-8'))
        function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'parse_content')
        scope = {'get_parser': lambda _: parse}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(ROOT / 'main.py'), 'exec'), scope)
        result = scope['parse_content']('anytls://p@host:443#good\nanytls://broken')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['tag'], 'good')


if __name__ == '__main__':
    unittest.main()
