"""Download verified contracts; run audit_downloads.py separately."""
import argparse
from decimal import Decimal
import logging
import sys
from pathlib import Path
import scan_blockscout as core
from chain_sources import AutoClient, SourcifyClient

CHAINS = {'eth': (1, 'https://eth.blockscout.com'), 'base': (8453, 'https://base.blockscout.com'),
          'bnb': (56, 'https://sourcify.dev/chain/56'), 'optimism': (10, 'https://optimism.blockscout.com'),
          'robinhood': (4663, 'https://robinhoodchain.blockscout.com'), 'polygon': (137, 'https://polygon.blockscout.com'),
          'arbitrum': (42161, 'https://arbitrum.blockscout.com'), 'avalanche': (43114, 'https://sourcify.dev/chain/43114'),
          'hyperliquid': (999, 'https://sourcify.dev/chain/999')}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chains', nargs='+', choices=CHAINS, default=list(CHAINS))
    p.add_argument('--target', type=int, default=50)
    p.add_argument('--min-usd', type=Decimal, default=Decimal('10000'))
    p.add_argument('--max-pages', type=int, default=100000)
    p.add_argument('--interval', type=float, default=1.0)
    args = p.parse_args(argv)
    if args.target < 1 or args.max_pages < 1 or args.interval < .25 or not args.min_usd.is_finite() or args.min_usd < 0:
        p.error('Invalid target, minimum, page count or interval')
    status = 0
    for chain in dict.fromkeys(args.chains):
        chainid, url = CHAINS[chain]
        client = SourcifyClient(chain, url, args.interval) if chain in ('bnb', 'avalanche', 'hyperliquid') else AutoClient(chain, url, args.interval)
        core.LOG.info('CHAIN %s (%s): downloading up to %s new contracts', chain, chainid, args.target)
        command = ['--funded', '--explorer', url, '--target', str(args.target), '--min-usd', str(args.min_usd),
                   '--interval', str(args.interval), '--max-pages', str(args.max_pages),
                   '--output', str((Path(__file__).resolve().parent / 'contracts') / chain),
                   '--metadata-dir', str((Path(__file__).resolve().parent / 'metadata') / chain),
                   '--failed-dir', str((Path(__file__).resolve().parent / 'failed') / chain)]
        try:
            if core.main(command, client=client): status = 2
        except (core.APIError, OSError, ValueError, KeyError, TypeError) as exc:
            core.LOG.error('%s failed: %s; continuing', chain, exc)
            status = 2
    return status

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    sys.exit(main())

