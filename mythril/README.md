# Mythril downloader and scanner

Windows + Python 3.10+ + Docker Desktop. The pipeline discovers verified contracts on Ethereum, Optimism, and Avalanche and runs the original Mythril Docker image (v0.24.8) immediately after each download. The process is sequential: discovery pauses during each audit. It keeps sources and writes text reports in `scanner/reports/<chain>`; failed and partial scans are identified rather than marked clean. Findings need manual validation, particularly proxy and delegatecall warnings. This tool does not prove deployed contracts are exploitable or secure.

The analyzer explores up to one transaction (`-t 1`) for faster triage; vulnerabilities requiring multiple transactions can be missed.

Discovery filters for names or custom source mentioning vaults, lending, deposits, staking, exchanges, bridges and related features. It retains OpenZeppelin dependencies. This heuristic can both miss relevant contracts and include safe ones.

Start Docker Desktop and wait for its engine, then in PowerShell:

```powershell
& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\jojd1\Documents\ChatGPT\solidityaudit\mythril\Run.ps1'
```

The target is 20 saved contracts per chain, including those from earlier runs. Change with `-Target 5`; analysis wall timeout with `-TimeoutSeconds 120`. Contract discovery currently requires approximately $10,000 in indexed priced holdings; prices may be incomplete or stale. Explorer availability, rate limits, compilation errors, unsupported compiler versions and timeouts may prevent the target. Avalanche uses Sourcify and RPC; other chains use Blockscout with fallback. Solidity compiler downloads and discovery need internet. Each report may have an associated source ZIP. Retain `scanner/metadata` and `scanner/contracts` for retries. Do not run multiple copies simultaneously in the same folder.

Run `python scanner/run_pipeline.py --help` for more options. Docker image digest: `sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff`.

