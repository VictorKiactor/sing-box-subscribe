"""AnyTLS support for Clash subscriptions and share links."""

import math
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit


def _duration(value):
    text = str(value).strip()
    if not text:
        raise ValueError('Empty AnyTLS duration')
    try:
        seconds = float(text)
    except ValueError:
        return text
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError('Invalid AnyTLS duration')
    return format(seconds, 'g') + 's'


def to_uri(proxy):
    """Preserve fields through the existing Clash -> URI -> outbound pipeline."""
    server = str(proxy['server'])
    if ':' in server and not server.startswith('['):
        server = '[' + server + ']'
    params = {}
    for key in ('sni', 'client-fingerprint', 'idle-session-check-interval',
                'idle-session-timeout', 'min-idle-session', 'client-metadata'):
        value = proxy.get(key)
        if value is not None and value != '':
            params['fp' if key == 'client-fingerprint' else key] = str(value)
    if proxy.get('servername') and not params.get('sni'):
        params['sni'] = str(proxy['servername'])
    alpn = proxy.get('alpn')
    if alpn:
        params['alpn'] = ','.join(alpn) if isinstance(alpn, list) else str(alpn)
    insecure = proxy.get('skip-cert-verify', False)
    params['insecure'] = '1' if str(insecure).lower() in ('true', '1') else '0'
    return 'anytls://{}@{}:{}?{}#{}'.format(
        quote(str(proxy['password']), safe=''), server, int(proxy['port']),
        urlencode(params), quote(str(proxy.get('name', 'AnyTLS')), safe=''),
    )


def parse(data):
    info = urlsplit(data)
    if info.scheme != 'anytls' or '@' not in info.netloc:
        raise ValueError('Invalid AnyTLS share link')
    port = info.port
    if not info.hostname or port is None or not 1 <= port <= 65535:
        raise ValueError('Invalid AnyTLS endpoint')
    params = {key: values[-1] for key, values in parse_qs(info.query).items()}
    tls = {'enabled': True, 'insecure': False}
    insecure = params.get('insecure', params.get('allowInsecure', '0'))
    tls['insecure'] = str(insecure).lower() in ('1', 'true')
    if params.get('sni') or params.get('peer'):
        tls['server_name'] = params.get('sni') or params['peer']
    if params.get('alpn'):
        tls['alpn'] = params['alpn'].split(',')
    if params.get('fp'):
        tls['utls'] = {'enabled': True, 'fingerprint': params['fp']}
    node = {
        'tag': unquote(info.fragment) or 'AnyTLS-' + info.hostname,
        'type': 'anytls', 'server': info.hostname, 'server_port': port,
        'password': unquote(info.netloc.rsplit('@', 1)[0]), 'tls': tls,
    }
    for key in ('idle-session-check-interval', 'idle-session-timeout'):
        if key in params:
            node[key.replace('-', '_')] = _duration(params[key])
    if 'min-idle-session' in params:
        value = int(params['min-idle-session'])
        if value < 0:
            raise ValueError('Negative AnyTLS min-idle-session')
        node['min_idle_session'] = value
    if 'client-metadata' in params:
        node['client_metadata'] = params['client-metadata']
    return node
