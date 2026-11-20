"""Generate separate collection, EVM and reconciliation inputs for a development seller."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from time import time
import uuid

from stack_config import PORTS, dump, save_env

SPEC = Path(__file__).with_name("deposit_spec.json")
CONTRACT = "0x55d398326f99059fF775485246999027B3197955"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def digest(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def ledger_units(raw):
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal() or raw.startswith("0") or len(raw) > 78:
        raise ValueError("expected positive canonical raw USDT amount")
    units = int(raw) // 10**12
    if not 0 < units < 2**63:
        raise ValueError("amount outside bookable USDT range")
    return units


def generate(out, account_id, spec_path=SPEC):
    seller = uuid.UUID(account_id)
    if seller.version != 7 or str(seller) != account_id:
        raise ValueError("expected canonical seller account UUIDv7")
    spec = json.loads(spec_path.read_text())
    latest, finalized = spec["latest"], spec["finalized"]
    if not 0 <= finalized <= latest <= 10000 or spec["block_seconds"] <= 0:
        raise ValueError("invalid block range")
    genesis = int(time())  # All blocks in this dataset share one generation clock.
    # Use the seller UUIDv7 millisecond and deterministic fixture entropy for
    # the address ID, so regenerating a seller produces the same wallet code.
    address_bytes = bytearray(seller.bytes[:6] + bytes.fromhex(digest("address-id", account_id))[:10])
    address_bytes[6] = (address_bytes[6] & 0x0f) | 0x70
    address_bytes[8] = (address_bytes[8] & 0x3f) | 0x80
    address_id = str(uuid.UUID(bytes=bytes(address_bytes)))
    address = "0x" + digest("recipient", account_id)[-40:]
    if "address_id" in spec or "deposit_address" in spec:
        address_id, address = spec.get("address_id", ""), spec.get("deposit_address", "")
        parsed = uuid.UUID(address_id)
        if parsed.version != 7 or str(parsed) != address_id or len(address) != 42 or not address.startswith("0x"):
            raise ValueError("invalid development address binding")
        if len(bytes.fromhex(address[2:])) != 20 or int(address[2:], 16) == 0:
            raise ValueError("invalid EVM address")
        address = address.lower()
    binding = dict(account_id=account_id, address_id=address_id, deposit_address=address,
                   wallet_account_code="collection_wallet:USDT:BSC:" + address_id)
    claims, receipts, blocks = {}, {}, []
    parent = "0x" + "00" * 32
    for height in range(latest + 1):
        timestamp = genesis + height * spec["block_seconds"]
        transfers = [t for t in spec["transfers"] if t["block"] == height]
        txs = ["0x" + digest("transfer", address, t["key"], t["chain_raw"]) for t in transfers]
        block_hash = "0x" + digest("block", height, parent, timestamp, txs)
        block = dict(number=hex(height), hash=block_hash, parentHash=parent, timestamp=hex(timestamp), transactions=txs)
        blocks.append(block)
        parent = block_hash
        # Each transaction in this fixture emits one Transfer. logIndex is block-wide.
        for index, (transfer, tx) in enumerate(zip(transfers, txs)):
            key = transfer["key"]
            if height == 0 or not key or key in claims:
                raise ValueError("invalid transfer key or height")
            raw = transfer["chain_raw"]
            ledger_units(raw)
            claimed = transfer.get("receipt_raw", raw)
            claims[key] = dict(chain_transaction_id=tx, transfer_index=index, raw_amount=claimed, units=ledger_units(claimed),
                               block_number=height, block_hash=block_hash,
                               confirmed_at=datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            location = dict(transactionHash=tx, transactionIndex=hex(index), blockHash=block_hash, blockNumber=hex(height))
            log = dict(**location, address=CONTRACT, logIndex=hex(index), removed=False, data=f"0x{int(raw):064x}",
                       topics=[TRANSFER, "0x" + "00" * 12 + "11" * 20, "0x" + address[2:].zfill(64)])
            receipts[tx] = dict(**location, status="0x1", logs=[log])
    if len(claims) != len(spec["transfers"]) or not claims:
        raise ValueError("transfers must be within the generated chain")
    replay_key = spec.get("replay_key", next(iter(claims)))
    if replay_key not in claims:
        raise ValueError("replay must reference an existing transfer")
    # Publish the inputs together. Never replace an existing funded seller's dataset.
    if out.exists():
        raise ValueError("deposit dataset already exists")
    with tempfile.TemporaryDirectory(dir=out.parent) as tmp:
        stage = Path(tmp) / "deposits"
        stage.mkdir(mode=0o700)
        dump(stage / "scenario.json", dict(chain_id=31337, **binding, receipts=claims, replay_key=replay_key))
        dump(stage / "chain.json", dict(chain_id=31337, finalized=finalized, blocks=blocks, receipts=receipts))
        dump(stage / "bindings.json", dict(version="dev-bindings-v1", bindings=[
            dict(**binding, valid_from_block=1, valid_to_block=latest)]))
        save_env(stage / "reconciliation.env", {
            "AIPAY_RECON_POLL_INTERVAL": "1s", "AIPAY_RECON_BATCH": "100",
            "AIPAY_RECON_EVM_RPC_URL": f"http://127.0.0.1:{PORTS['devchain']}", "AIPAY_RECON_EVM_TIMEOUT": "5s",
            "AIPAY_RECON_EVM_CHAIN_ID": "31337", "AIPAY_RECON_EVM_REGISTRY_VERSION": "bsc-usdt-v1",
            "AIPAY_RECON_BINDINGS_FILE": out.resolve() / "bindings.json",
            "AIPAY_RECON_SCREENING_MODE": "development_allow", "AIPAY_RECON_SCREENING_POLICY": "seller-deposit-v1"})
        stage.rename(out)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seller-account-id", required=True)
    parser.add_argument("--spec", type=Path, default=SPEC)
    args = parser.parse_args()
    generate(args.out, args.seller_account_id, args.spec)
