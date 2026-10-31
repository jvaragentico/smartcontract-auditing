"""Sourcify + public RPC fallback. Standard library only; no API keys."""
import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
import scan_blockscout as core

CONFIG = {
    'bnb': (56, 'https://bsc-rpc.publicnode.com', 'coingecko:binancecoin'),
    'base': (8453, 'https://base-rpc.publicnode.com', 'coingecko:ethereum'),
    'eth': (1, 'https://ethereum-rpc.publicnode.com', 'coingecko:ethereum'),
    'optimism': (10, 'https://optimism-rpc.publicnode.com', 'coingecko:ethereum'),
    'robinhood': (4663, 'https://rpc.mainnet.chain.robinhood.com', 'coingecko:ethereum'),
    'polygon': (137, 'https://polygon-bor-rpc.publicnode.com', 'coingecko:polygon-ecosystem-token'),
    'arbitrum': (42161, 'https://arb1.arbitrum.io/rpc', 'coingecko:ethereum'),
    'avalanche': (43114, 'https://api.avax.network/ext/bc/C/rpc', 'coingecko:avalanche-2'),
    'hyperliquid': (999, 'https://rpc.hyperliquid.xyz/evm', 'coingecko:hyperliquid'),
}
# Exact addresses, never ticker matching. Fallback coverage is deliberately explicit.
TOKENS = {
    'hyperliquid': [],
    'bnb': ['0x55d398326f99059ff775485246999027b3197955',
            '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
            '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c'],
    'base': ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
             '0x4200000000000000000000000000000000000006'],
    'optimism': ['0x0b2c639c533813f4aa9d7837caf62653d097ff85',
                 '0x4200000000000000000000000000000000000006'],
    'eth': ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
            '0xdac17f958d2ee523a2206206994597c13d831ec7',
            '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'],
    'robinhood': [],
    'polygon': ['0x3c499c542cef5e3811e1192ce70d8cc03d5c3359',
                '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619'],
    'arbitrum': ['0xaf88d065e77c8cc2239327c5edb3a432268e5831',
                 '0x82af49447d8a07e3bd95bd0d56f35241523fbab1'],
    'avalanche': ['0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e',
                  '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7'],
}
LLAMA_CHAIN = {'bnb': 'bsc', 'eth': 'ethereum', 'base': 'base', 'optimism': 'optimism',
               'robinhood': 'robinhood', 'polygon': 'polygon',
               'arbitrum': 'arbitrum', 'avalanche': 'avax', 'hyperliquid': 'hyperliquid'}


class SourcifyClient(core.Client):
    def __init__(self, chain, base, interval=1):
        super().__init__(base, interval)
        self.chain = chain
        self.chainid, self.rpc_url, self.coin = CONFIG[chain]
        self.quotes, self.quote_time, self.network_checked = {}, 0, False

    def request(self, url, body=None):
        for attempt in range(4):
            time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            try:
                req = Request(url, data=json.dumps(body).encode() if body else None,
                              headers={'User-Agent': 'ContractExtractor/1.0', 'Accept': 'application/json',
                                       'Content-Type': 'application/json'})
                with urlopen(req, timeout=35) as response:
                    return json.load(response)
            except HTTPError as exc:
                if exc.code != 429 and exc.code < 500:
                    raise core.APIError(f'HTTP {exc.code} at {url.split("?")[0]}') from None
            except (URLError, OSError, TimeoutError, ValueError):
                pass
            if attempt < 3:
                core.LOG.warning('Fallback API retry %s/3', attempt + 1)
                time.sleep(2 ** attempt)
        raise core.APIError('Fallback API retry budget exhausted')

    def rpc(self, method, params):
        if not self.network_checked:
            data = self.request(self.rpc_url, {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []})
            if int(data.get('result', '0x0'), 16) != self.chainid:
                raise core.APIError('RPC chain ID does not match requested chain')
            self.network_checked = True
        data = self.request(self.rpc_url, {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
        if data.get('error') or data.get('result') is None:
            raise core.APIError(f'RPC failed: {method}')
        return data['result']

    def prices(self):
        if time.time() - self.quote_time > 300:
            ids = [self.coin] + [LLAMA_CHAIN[self.chain] + ':' + token for token in TOKENS[self.chain]]
            data = self.request('https://coins.llama.fi/prices/current/' + ','.join(ids))
            self.quotes = data.get('coins', {})
            self.quote_time = time.time()
        return self.quotes

    def price(self, identifier):
        row = self.prices().get(identifier, {})
        if not 0 <= time.time() - int(row.get('timestamp', 0)) <= 3600:
            return None
        return row.get('price')

    def get(self, path, params=None):
        params = params or {}
        if path == '/addresses':
            query = {'limit': 200, 'sort': 'desc'}
            if params.get('afterMatchId'):
                query['afterMatchId'] = params['afterMatchId']
            data = self.request(f'https://sourcify.dev/server/v2/contracts/{self.chainid}?' + urlencode(query))
            rows = data.get('results')
            if not isinstance(rows, list):
                raise core.APIError('Invalid Sourcify discovery response')
            return {'items': [{'hash': row['address'], 'is_contract': True, 'is_verified': True}
                              for row in rows if row.get('match') in ('exact_match', 'match')],
                    'next_page_params': {'afterMatchId': rows[-1]['matchId']} if len(rows) == 200 else None}
        address = path.split('/')[-1] if not path.endswith('/tokens') else path.split('/')[-2]
        if not core.ADDRESS.fullmatch(address):
            raise core.APIError('Invalid address in fallback request')
        if path.startswith('/smart-contracts/'):
            data = self.request(f'https://sourcify.dev/server/v2/contract/{self.chainid}/{address}?fields=sources,compilation')
            compilation = data.get('compilation') or {}
            sources = [(name, item['content']) for name, item in (data.get('sources') or {}).items()
                       if name.lower().endswith('.sol') and isinstance(item, dict) and isinstance(item.get('content'), str)]
            if not sources or compilation.get('language', '').lower() != 'solidity':
                raise core.APIError('No verified Solidity source in Sourcify')
            # The first source may be a library. Audit the verified contract's
            # actual entry file when Sourcify supplies its fully qualified name.
            qualified = compilation.get('fullyQualifiedName') or ''
            entry = qualified.rsplit(':', 1)[0] if ':' in qualified else None
            if entry:
                selected = [item for item in sources if item[0] == entry]
                if not selected:
                    raise core.APIError('Verified contract entry source is missing')
                sources = selected + [item for item in sources if item[0] != entry]
            settings = compilation.get('compilerSettings') or {}
            return dict(is_verified=data.get('match') in ('exact_match', 'match'), language='solidity',
                        name=compilation.get('name'), compiler_version=compilation.get('compilerVersion'),
                        compiler_settings=settings, optimization_enabled=settings.get('optimizer', {}).get('enabled'),
                        optimization_runs=settings.get('optimizer', {}).get('runs'),
                        is_fully_verified=data.get('match') == 'exact_match', file_path=sources[0][0], source_code=sources[0][1],
                        additional_sources=[{'file_path': name, 'source_code': content} for name, content in sources[1:]])
        if path.endswith('/tokens'):
            items = []
            for token in TOKENS[self.chain]:
                amount = int(self.rpc('eth_call', [{'to': token, 'data': '0x70a08231' + address[2:].rjust(64, '0')}, 'latest']), 16)
                places = int(self.rpc('eth_call', [{'to': token, 'data': '0x313ce567'}, 'latest']), 16)
                items.append({'value': str(amount), 'token': {'address_hash': token, 'type': 'ERC-20',
                              'decimals': str(places), 'exchange_rate': self.price(LLAMA_CHAIN[self.chain] + ':' + token)}})
            return {'items': items, 'next_page_params': None}
        if path.startswith('/addresses/'):
            return dict(is_contract=self.rpc('eth_getCode', [address, 'latest']) not in ('0x', '0x0'), is_verified=True,
                        coin_balance=str(int(self.rpc('eth_getBalance', [address, 'latest']), 16)),
                        exchange_rate=self.price(self.coin), valuation_coverage='native_and_common_tokens_only')
        raise core.APIError('Fallback supports funded mode only')


class AutoClient(core.Client):
    def __init__(self, chain, base, interval=1):
        super().__init__(base, interval)
        self.chain = chain
        self.fallback = None

    def get(self, path, params=None):
        if self.fallback:
            return self.fallback.get(path, params)
        try:
            return super().get(path, params)
        except core.APIError as exc:
            # Change discovery source only before receiving any candidate pages.
            if path != '/addresses' or params or 'HTTP 403' not in str(exc):
                raise
            core.LOG.warning('%s public explorer denied access; using Sourcify + RPC (common-token coverage)', self.chain)
            self.fallback = SourcifyClient(self.chain, self.base, self.interval)
            return self.fallback.get(path, params)

