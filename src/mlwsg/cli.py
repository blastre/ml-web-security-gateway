import argparse
import json

from mlwsg.catalogue import LAYERS, load


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mlwsg", description="SSRF research lab tooling")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("attacks", help="list the attack catalogue").add_argument(
        "--layer", choices=LAYERS
    )
    sub.add_parser("assets", help="list protected assets and their address ranges")
    generate = sub.add_parser("generate", help="create a reproducible synthetic dataset")
    generate.add_argument("--output", default="artifacts/dataset.csv")
    generate.add_argument("--per-family", type=int, default=20)
    generate.add_argument("--seed", type=int, default=20240501)
    train = sub.add_parser("train", help="train baseline models and report held-out metrics")
    train.add_argument("--data", default="artifacts/dataset.csv")
    train.add_argument("--output", default="artifacts/models/model.joblib")
    score = sub.add_parser("score", help="score a URL using the trained model")
    score.add_argument("url")
    score.add_argument("--model", default="artifacts/models/model.joblib")
    incidents = sub.add_parser("incidents", help="list blocked incidents")
    incidents.add_argument("--db", default="artifacts/incidents.sqlite")
    incident = sub.add_parser("incident", help="inspect or review a blocked incident")
    incident.add_argument("id", type=int)
    incident.add_argument("action", choices=("show", "analyse", "approve", "reject"))
    incident.add_argument("--db", default="artifacts/incidents.sqlite")
    incident.add_argument("--provider", default="codex")
    args = parser.parse_args(argv)
    if args.command == "generate":
        from mlwsg.dataset import generate as generate_dataset

        print(json.dumps(generate_dataset(args.output, args.per_family, args.seed), indent=2))
        return
    if args.command == "train":
        from mlwsg.models import train as train_models

        print(json.dumps(train_models(args.data, args.output), indent=2))
        return
    if args.command == "score":
        from mlwsg.models import predict_url

        print(predict_url(args.url, args.model))
        return
    if args.command in ("incidents", "incident"):
        from mlwsg.incidents import IncidentStore

        store = IncidentStore(args.db)
        if args.command == "incidents":
            result = store.list()
        elif args.action == "show":
            result = store.get(args.id)
        elif args.action == "approve":
            store.approve(args.id)
            result = store.get(args.id)
        elif args.action == "reject":
            store.reject(args.id)
            result = store.get(args.id)
        else:
            from mlwsg.agent import analyse_incident

            result = analyse_incident(store, args.id, args.provider)
        print(json.dumps(result, indent=2))
        return

    catalogue = load()
    if args.command == "assets":
        for asset in catalogue.assets.values():
            nets = ", ".join(map(str, asset.networks)) or "-"
            print(f"{asset.name:<11} {nets:<40} {asset.description}")
        return

    for a in catalogue.attacks:
        if not args.layer or args.layer in a.layers:
            print(f"{a.id}  {a.vector:<8} {a.asset:<10} {'+'.join(a.layers):<14} {a.payload}")
