import argparse

from mlwsg.catalogue import LAYERS, load


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mlwsg", description="SSRF research lab tooling")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("attacks", help="list the attack catalogue").add_argument(
        "--layer", choices=LAYERS
    )
    sub.add_parser("assets", help="list protected assets and their address ranges")
    args = parser.parse_args(argv)

    catalogue = load()
    if args.command == "assets":
        for asset in catalogue.assets.values():
            nets = ", ".join(map(str, asset.networks)) or "-"
            print(f"{asset.name:<11} {nets:<40} {asset.description}")
        return

    for a in catalogue.attacks:
        if not args.layer or args.layer in a.layers:
            print(f"{a.id}  {a.vector:<8} {a.asset:<10} {'+'.join(a.layers):<14} {a.payload}")
