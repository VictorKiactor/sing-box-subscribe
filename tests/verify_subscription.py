"""Offline real-subscription regression; input via stdin, never log credentials."""

import contextlib
import copy
import io
import json
import pathlib
import sys
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import main
import tool

payload = json.load(sys.stdin)
main.providers = {'exclude_protocol': 'ssr', 'subscribes': [],
                  'auto_set_outbounds_dns': {'proxy': '', 'direct': ''}}
main.init_parsers()
with contextlib.redirect_stdout(io.StringIO()):
    with patch.object(main, 'get_content_from_url', return_value=payload['subscription']):
        nodes = main.get_nodes('https://subscription.invalid/')
    # The source includes a fake SS node containing only the download timestamp.
    main.nodefilter(nodes, {'ex-node-name': '拉取于'})
    data = {'tag_1': nodes}
    tool.proDuplicateNodeName(data)
    config = main.combin_to_config(copy.deepcopy(payload['template']), data)
assert len(nodes) == payload['expected_nodes'], 'Unexpected node loss during conversion'
assert all(node['type'] == 'anytls' for node in nodes), 'Metadata node was not excluded'
source_nodes = [node for node in payload['subscription']['proxies'] if node['type'] == 'anytls']
for source, node in zip(source_nodes, nodes):
    assert source['password'] == node['password'], 'Password changed during conversion'
    assert source['sni'] == node['tls']['server_name'], 'SNI changed during conversion'
    assert source['skip-cert-verify'] == node['tls']['insecure'], 'Certificate policy changed'
    assert source['alpn'] == node['tls']['alpn'], 'ALPN changed during conversion'
    assert node['idle_session_check_interval'] == '30s'
    assert node['idle_session_timeout'] == '30s'
    assert node['min_idle_session'] == 0
tags = {node['tag'] for node in config['outbounds']}
groups = []
for outbound in config['outbounds']:
    if 'outbounds' not in outbound:
        continue
    assert outbound['outbounds'], 'Empty group'
    assert all(tag in tags for tag in outbound['outbounds']), 'Dangling outbound reference'
    assert 'filter' not in outbound, 'Converter-only field leaked into sing-box config'
    assert all('拉取于' not in tag for tag in outbound['outbounds'])
    groups.append({'tag': outbound['tag'], 'count': len(outbound['outbounds'])})
output = ROOT / '.private-validation'
output.mkdir(exist_ok=True)
(output / 'config.json').write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({'real_nodes': len(nodes), 'anytls_nodes': len(source_nodes), 'groups': groups,
                  'credentials_and_tls_preserved': True, 'output': str(output / 'config.json')}, ensure_ascii=False))
