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
    agent = sub.add_parser("agent", help="ask the SSRF agent: is this SSRF, which technique, why")
    target = agent.add_mutually_exclusive_group(required=True)
    target.add_argument("url", nargs="?")
    target.add_argument("--line", type=int, help="analyse row N of --data instead of a URL")
    agent.add_argument("--data", default="artifacts/dataset.csv")
    agent.add_argument("--model", default="artifacts/models/model.joblib")
    agent.add_argument("--backend", choices=("offline", "claude"), default="offline")
    agent.add_argument("--llm-model", default="claude-opus-5-5")
    agent.add_argument(
        "--effort", choices=("low", "medium", "high", "xhigh", "max"), default="medium"
    )
    agent.add_argument(
        "--sensitivity", choices=("aggressive", "balanced", "conservative"), default="balanced"
    )
    agent.add_argument(
        "--resolver", choices=("lab", "system"), default="lab", help="lab = deterministic lab DNS"
    )
    agent.add_argument("--memory", help="long-term memory SQLite (see mlwsg memory seed)")
    agent.add_argument("--no-knowledge", action="store_true")
    agent.add_argument("--trace", action="store_true", help="include thoughts/actions/observations")
    memory = sub.add_parser("memory", help="initialise the agent's long-term memory")
    memory.add_argument("action", choices=("seed",))
    memory.add_argument("--data", default="artifacts/dataset.csv")
    memory.add_argument("--model", default="artifacts/models/model.joblib")
    memory.add_argument("--memory", default="artifacts/agent_memory.sqlite")
    memory.add_argument("--per-family", type=int, default=3)
    evaluate = sub.add_parser("evaluate", help="benchmark the agent against its classifiers")
    evaluate.add_argument("--data", default="artifacts/dataset.csv")
    evaluate.add_argument("--model", default="artifacts/models/model.joblib")
    evaluate.add_argument("--backend", choices=("offline", "claude"), default="offline")
    evaluate.add_argument("--limit", type=int, help="cap held-out rows (LLM cost control)")
    evaluate.add_argument("--output", default="artifacts/evaluation.json")
    evaluate.add_argument(
        "--external", help="extra test set CSV with url,label[,technique] columns"
    )
    args = parser.parse_args(argv)
    if args.command == "agent":
        from mlwsg.memory import LongTermMemory
        from mlwsg.ssrf_agent import SSRFAgent
        from mlwsg.tools import LabResolver, dataset_line, system_resolver

        url = args.url
        if args.line is not None:
            url = dataset_line(args.data, args.line)["url"]
        ssrf_agent = SSRFAgent(
            args.model,
            backend=args.backend,
            sensitivity=args.sensitivity,
            resolver=LabResolver() if args.resolver == "lab" else system_resolver,
            memory=LongTermMemory(args.memory) if args.memory else None,
            use_knowledge=not args.no_knowledge,
            llm_model=args.llm_model,
            effort=args.effort,
        )
        print(json.dumps(ssrf_agent.analyse(url).to_dict(trace=args.trace), indent=2))
        return
    if args.command == "memory":
        from mlwsg.evaluate import load_split, seed_memory
        from mlwsg.memory import LongTermMemory
        from mlwsg.ssrf_agent import SSRFAgent
        from mlwsg.tools import LabResolver

        store = LongTermMemory(args.memory)
        seeder = SSRFAgent(args.model, resolver=LabResolver(), memory=store)
        rows = load_split(args.data, "train", per_family=args.per_family)
        stored = seed_memory(seeder, rows)
        print(json.dumps({"path": args.memory, "sessions": len(rows), "stored": stored}))
        return
    if args.command == "evaluate":
        from pathlib import Path

        from mlwsg.evaluate import evaluate as run_evaluation
        from mlwsg.evaluate import markdown

        report = run_evaluation(
            args.data, args.model, backend=args.backend, limit=args.limit, external=args.external
        )
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(markdown(report))
        print(f"\nFull report: {args.output}")
        return
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
