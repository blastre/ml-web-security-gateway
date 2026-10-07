"""Command line and interactive TUI."""

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ssrf_agent import evaluate as evaluation
from ssrf_agent import memory, models, pipeline
from ssrf_agent.config import settings

app = typer.Typer(help="SSRF detection agent (IDS-Agent architecture).", no_args_is_help=True)
console = Console()
STAGES = {"fast_rules": "Fast rules", "agent": "Agent", "egress": "Egress guard"}
STYLE = {"allow": "green", "block": "red", "uncertain": "yellow"}


def banner() -> Panel:
    return Panel(
        Text.assemble(
            ("SSRF Agent", "bold cyan"),
            "  ·  IDS-Agent architecture\n",
            ("model ", "dim"),
            (settings.model_label, "bold"),
            ("   sensitivity ", "dim"),
            (settings.sensitivity, "bold"),
            ("   memory ", "dim"),
            (f"{memory.size()} cases", "bold"),
        ),
        border_style="cyan",
    )


class View:
    """Live view of one request moving through the flowchart."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.stages: dict[str, tuple[str, str]] = {}
        self.trace = Tree("[bold]Agent reasoning[/]", guide_style="dim")
        self.agent_used = False
        self.decision: pipeline.Decision | None = None

    def on_event(self, kind: str, data: Any) -> None:
        if kind == "stage":
            stage, outcome, reason = data
            self.stages[stage] = (outcome, reason)
        elif kind == "thought":
            self.agent_used = True
            self.trace.add(f"[italic]💭 {data[:300]}[/]")
        elif kind == "action" and data["tool"] != "StructuredOutput":
            self.agent_used = True
            args = ", ".join(f"{k}={v}" for k, v in data["input"].items())
            self.node = self.trace.add(f"[cyan]🔧 {data['tool']}[/]({args})")
        elif kind == "observation" and "Structured output" not in str(data):
            getattr(self, "node", self.trace).add(f"[dim]{str(data)[:220]}[/]")

    def flow(self) -> Text:
        text = Text()
        for i, (key, label) in enumerate(STAGES.items()):
            if i:
                text.append("  →  ", style="dim")
            if key in self.stages:
                outcome = self.stages[key][0]
                text.append(f"● {label} ({outcome})", style=f"bold {STYLE[outcome]}")
            elif self.decision is None and (
                key == "agent"
                and "fast_rules" in self.stages
                and self.stages["fast_rules"][0] == "uncertain"
            ):
                text.append(f"◌ {label} (thinking…)", style="yellow")
            else:
                text.append(f"○ {label}", style="dim")
        return text

    def __rich__(self) -> Group:
        parts: list[Any] = [Text(self.url, style="bold"), self.flow()]
        if fast := self.stages.get("fast_rules"):
            parts.append(Text(f"fast rules: {fast[1]}", style="dim"))
        if self.agent_used:
            parts.append(self.trace)
        if d := self.decision:
            blocked = d.action == "block"
            body = Text.assemble(
                ("BLOCKED" if blocked else "ALLOWED", f"bold {STYLE[d.action]}"),
                (f"   decided by {STAGES[d.stage]}\n", "dim"),
            )
            if v := d.verdict:
                body.append(
                    f"verdict {v.verdict.upper()}   technique {v.technique_id}   "
                    f"confidence {v.confidence:.2f}\n",
                    style="bold",
                )
            body.append(d.reason)
            parts.append(Panel(body, border_style=STYLE[d.action], title="Decision"))
        return Group(*parts)


def show(url: str) -> pipeline.Decision:
    view = View(url)
    with Live(view, console=console, refresh_per_second=8, transient=False):
        view.decision = asyncio.run(pipeline.decide(url, view.on_event))
    return view.decision


@app.command()
def train() -> None:
    """Train the three classifiers on the technique catalogue."""
    console.print(models.train())


@app.command()
def check(url: str) -> None:
    """Run one URL through the pipeline with a live trace."""
    console.print(banner())
    show(url)


@app.command()
def interactive() -> None:
    """Paste URLs (or pick a sample number) and watch the agent decide."""
    samples = evaluation.load_csv(settings.data_dir / "samples.csv")
    console.print(banner())
    console.print("[dim]Enter a URL, a sample number (`s` lists them) or `q` to quit.[/]")
    while True:
        entry = Prompt.ask("\n[bold cyan]url[/]").strip()
        if entry in ("q", "quit", "exit"):
            return
        if entry == "s":
            table = Table("#", "url", "label", box=None)
            for i, row in enumerate(samples, 1):
                table.add_row(str(i), row["url"], "ssrf" if row["label"] else "benign")
            console.print(table)
            continue
        if entry.isdigit() and 1 <= int(entry) <= len(samples):
            entry = samples[int(entry) - 1]["url"]
        if entry:
            show(entry)


@app.command()
def evaluate(
    csv_path: Annotated[Path, typer.Argument()] = settings.data_dir / "samples.csv",
    concurrency: int = 4,
    learn: bool = True,
) -> None:
    """Score a labelled CSV (url,label) through the full pipeline."""
    console.print(banner())

    def progress(row: dict, d: pipeline.Decision) -> None:
        ok = (d.action == "block") == bool(row["label"])
        console.print(
            f"{'[green]✓' if ok else '[red]✗'}[/] {d.action:5} "
            f"[dim]{d.stage:10}[/] {row['url'][:90]}"
        )

    report = asyncio.run(evaluation.run(csv_path, concurrency, learn, progress))
    table = Table(title=f"{report['rows']} URLs ({report['attacks']} SSRF) · {report['model']}")
    for col in ("Method", "Accuracy", "F1", "Recall", "False alarms"):
        table.add_column(col)
    rows = dict(report["methods"])
    if report["agent_only"]:
        rows["Agent (on the uncertain URLs it saw)"] = report["agent_only"]
    for name, m in rows.items():
        table.add_row(name, *(str(m[k]) for k in ("accuracy", "f1", "recall", "false_alarm_rate")))
    console.print(table)
    console.print("Decided by:", json.dumps(report["decided_by"]))
    for key in ("missed", "false_alarms"):
        if report[key]:
            console.print(f"[yellow]{key}:[/] " + ", ".join(report[key]))
    console.print(f"[dim]full results: {report['output']}[/]")


@app.command("memory-clear")
def memory_clear() -> None:
    """Empty long-term memory."""
    (settings.artifacts_dir / "memory.sqlite").unlink(missing_ok=True)
    console.print("memory cleared")
