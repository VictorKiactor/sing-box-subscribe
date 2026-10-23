import contextlib
import io
import json
import unittest
from unittest.mock import Mock, mock_open, patch
from urllib.parse import quote

import main
from api import app as web


class SubscriptionAPICompatibilityTests(unittest.TestCase):
    def convert_request(self, url):
        with web.app.test_request_context(url), \
                patch.object(web.subprocess, 'check_call') as run, \
                patch.object(web.os.path, 'exists', return_value=False), \
                patch('builtins.open', mock_open(read_data='{"outbounds":[]}')):
            response = web.config(web.request.view_args['url'])
        self.assertEqual(response.status_code, 200)
        args = run.call_args.args[0]
        return json.loads(json.loads(args[args.index('--temp_json_data') + 1]))

    def test_multi_parameter_subscription_and_padded_token(self):
        source = 'https://subscription.invalid/?sid=123&uid=456&token=example=='
        template = 'https://gist.githubusercontent.com/example/template/raw/config'
        config = self.convert_request('/config/' + source + '&ua=clash.meta&enn=' +
                                      quote('拉取于') + '&file=' + template)
        subscription = config['subscribes'][0]
        self.assertEqual(subscription['url'], source)
        self.assertEqual(subscription['User-Agent'], 'clash.meta')
        self.assertEqual(subscription['ex-node-name'], '拉取于')
        self.assertEqual(config['config_template'], template)

    def test_existing_clash_query_is_preserved(self):
        source = 'https://subscription.invalid/link/example?clash=1'
        template = 'https://gist.githubusercontent.com/example/template/raw/config'
        config = self.convert_request('/config/' + source + '&file=' + template)
        self.assertEqual(config['subscribes'][0]['url'], source)
        self.assertEqual(config['subscribes'][0]['User-Agent'], 'v2rayng')
        self.assertEqual(config['config_template'], template)

    def test_retry_preserves_user_agent_and_redacts_token(self):
        source = 'https://subscription.invalid/?token=private-test-token'
        response = Mock(content=b'anytls://test@proxy.example.com:443#test')
        providers = {'subscribes': [{'url': source, 'enabled': True,
                                     'User-Agent': 'clash.meta'}]}
        output = io.StringIO()
        with patch.object(main, 'providers', providers), \
                patch.object(main.tool, 'getResponse', side_effect=[None, response]) as fetch, \
                patch.object(main.time, 'sleep'), contextlib.redirect_stdout(output):
            content = main.get_content_from_url(source)
        self.assertTrue(content.startswith('anytls://'))
        self.assertEqual(fetch.call_count, 2)
        for call in fetch.call_args_list:
            self.assertEqual(call.kwargs['custom_user_agent'], 'clash.meta')
        self.assertNotIn('private-test-token', output.getvalue())


if __name__ == '__main__':
    unittest.main()
