"""Command-line interface."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import click

from . import __version__
from .config import EXAMPLE_CONFIG, Config, ConfigError
from .core.analysis import AnalysisCache, CallKind
from .core.project import Project
from .detectors import all_detectors, get_detector
from .engine import Scanner, collect_files
from .engine import write_baseline as save_baseline
from .findings import Confidence, Severity
from .reporters import EXTENSIONS, RENDERERS, render_console

SEVERITY_CHOICES = click.Choice([s.value for s in Severity], case_sensitive=False)
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class UsageError(click.ClickException):
    """Errors in how chainmail was invoked (exit code 2, distinct from 'findings found')."""

    exit_code = EXIT_ERROR


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="chainmail")
def main() -> None:
    """Chainmail - static analysis framework for auditing Solidity smart contracts."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["console", "json", "markdown", "html", "sarif"]),
    default="console",
    show_default=True,
    help="Format written to stdout.",
)
@click.option(
    "-o",
    "--output",
    "outputs",
    multiple=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write a report file; format inferred from extension (.json .md .html .sarif). Repeatable.",
)
@click.option("-c", "--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Configuration file.")
@click.option("-d", "--detectors", "include", multiple=True, help="Only run these detectors (comma-separated, wildcards allowed).")
@click.option("-x", "--exclude", multiple=True, help="Skip these detectors (comma-separated, wildcards allowed).")
@click.option("--min-severity", type=SEVERITY_CHOICES, help="Hide findings below this severity.")
@click.option("--min-confidence", type=click.Choice(["low", "medium", "high"]), help="Hide findings below this confidence.")
@click.option(
    "--fail-on", type=click.Choice([s.value for s in Severity] + ["none"]), help="Exit 1 if a finding at/above this severity remains."
)
@click.option("--baseline", type=click.Path(dir_okay=False, path_type=Path), help="Ignore findings listed in this baseline file.")
@click.option("--write-baseline", type=click.Path(dir_okay=False, path_type=Path), help="Record current findings as the new baseline.")
@click.option("--include-tests", is_flag=True, help="Also scan *.t.sol, test/ and script/.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colours.")
@click.option("-v", "--verbose", is_flag=True, help="Show recommendations in console output.")
@click.option("-q", "--quiet", is_flag=True, help="Print nothing on stdout (use with -o).")
def scan(
    paths,
    fmt,
    outputs,
    config_path,
    include,
    exclude,
    min_severity,
    min_confidence,
    fail_on,
    baseline,
    write_baseline,
    include_tests,
    no_color,
    verbose,
    quiet,
) -> None:
    """Scan Solidity files or directories."""
    try:
        config = Config.load(config_path, search_from=paths[0])
    except ConfigError as exc:
        raise UsageError(str(exc)) from exc
    if include:
        config.include_detectors = _split(include)
    if exclude:
        config.exclude_detectors += _split(exclude)
    if min_severity:
        config.min_severity = Severity.parse(min_severity)
    if min_confidence:
        config.min_confidence = Confidence(min_confidence)
    if fail_on:
        config.fail_on = None if fail_on == "none" else Severity.parse(fail_on)
    if include_tests:
        config.include_tests = True

    unknown = [d for d in config.include_detectors if "*" not in d and d not in all_detectors()]
    if unknown:
        raise UsageError(f"unknown detector(s): {', '.join(unknown)} (see `chainmail detectors`)")

    scanner = Scanner(config)
    try:
        files = collect_files(paths, config)
    except FileNotFoundError as exc:
        raise UsageError(str(exc)) from exc
    if not files:
        raise UsageError("no Solidity files found")
    result = scanner.scan_paths(paths, baseline=baseline)

    if write_baseline:
        n = save_baseline(result, write_baseline)
        click.echo(f"Baseline with {n} finding(s) written to {write_baseline}", err=True)

    for out in outputs:
        out_fmt = EXTENSIONS.get(out.suffix.lower())
        if out_fmt is None:
            raise UsageError(f"cannot infer report format from {out} (use .json, .md, .html or .sarif)")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(RENDERERS[out_fmt](result), encoding="utf-8")
        click.echo(f"Report written to {out}", err=True)

    if not quiet:
        if fmt == "console":
            color = False if no_color else None
            sys.stdout.write(render_console(result, color=color, verbose=verbose))
        else:
            sys.stdout.write(RENDERERS[fmt](result))

    if result.detector_errors:
        sys.exit(EXIT_ERROR)
    sys.exit(EXIT_FINDINGS if result.should_fail(config.fail_on) else EXIT_OK)


def _split(values) -> list[str]:
    out: list[str] = []
    for v in values:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


# ---------------------------------------------------------------------------
# detectors / explain
# ---------------------------------------------------------------------------
@main.command("detectors")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--markdown", "as_md", is_flag=True, help="Output as a Markdown table.")
def list_detectors(as_json: bool, as_md: bool) -> None:
    """List available detectors."""
    detectors = all_detectors()
    items = sorted(detectors.values(), key=lambda d: (-d.severity.rank, d.id))
    if as_json:
        click.echo(json.dumps([d.info() for d in items], indent=2))
        return
    if as_md:
        click.echo("| ID | Title | Severity | Confidence | SWC |")
        click.echo("|---|---|---|---|---|")
        for d in items:
            click.echo(f"| `{d.id}` | {d.title} | {d.severity.value} | {d.confidence.value} | {d.swc or '-'} |")
        return
    width = max(len(d.id) for d in items)
    click.echo(f"{'ID'.ljust(width)}  {'SEVERITY':9} {'CONF':6} {'SWC':8} TITLE")
    for d in items:
        click.echo(f"{d.id.ljust(width)}  {d.severity.value:9} {d.confidence.value:6} {(d.swc or '-'):8} {d.title}")
    click.echo(f"\n{len(items)} detectors")


@main.command()
@click.argument("detector_id")
def explain(detector_id: str) -> None:
    """Explain what a detector looks for and how to fix it."""
    try:
        d = get_detector(detector_id)
    except KeyError:
        raise UsageError(f"unknown detector {detector_id!r}") from None
    click.secho(f"{d.title}", bold=True)
    click.echo(f"id: {d.id}   severity: {d.severity.value}   confidence: {d.confidence.value}   category: {d.category}")
    if d.swc or d.cwe:
        click.echo("classification: " + ", ".join(x for x in (d.swc, d.cwe) if x))
    click.echo()
    click.echo(textwrap.fill(d.description, 88))
    if d.example:
        click.echo("\nExample:")
        click.echo(textwrap.indent(textwrap.dedent(d.example).strip("\n"), "    "))
    click.echo("\nRecommendation:")
    click.echo(textwrap.fill(d.recommendation, 88))
    if d.references:
        click.echo("\nReferences:")
        for r in d.references:
            click.echo(f"  - {r}")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------
@main.command()
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init(force: bool) -> None:
    """Create a chainmail.yml configuration file."""
    target = Path("chainmail.yml")
    if target.exists() and not force:
        raise UsageError("chainmail.yml already exists (use --force)")
    target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    click.echo("Created chainmail.yml")


# ---------------------------------------------------------------------------
# outline / callgraph
# ---------------------------------------------------------------------------
def _load_project(paths) -> Project:
    files = collect_files(paths, Config(include_tests=True))
    project = Project()
    for f in files:
        project.add_file(f)
    project.link()
    return project


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
def outline(paths) -> None:
    """Print the structure of contracts: inheritance, state, functions and guards."""
    project = _load_project(paths)
    cache = AnalysisCache(project)
    for info in project.iter_contracts():
        c = info.contract
        lin = " → ".join(i.name for i in info.linearization)
        click.secho(f"{c.kind} {c.name}", bold=True, nl=False)
        click.echo(f"  ({info.file.path}:{c.loc.line})")
        if len(info.linearization) > 1 or info.unresolved_bases:
            click.echo(f"  linearization: {lin}" + (f"  [unresolved: {', '.join(info.unresolved_bases)}]" if info.unresolved_bases else ""))
        for v in c.state_vars:
            flags = " ".join(x for x in (v.visibility, "constant" if v.is_constant else "", "immutable" if v.is_immutable else "") if x)
            click.echo(f"  ▪ {v.type_name} {v.name}" + (f"  [{flags}]" if flags else ""))
        for fn in c.modifiers + c.functions:
            fa = cache.get(fn, info)
            attrs = [x for x in (fn.visibility, fn.mutability) if x] + fn.modifier_names
            guard = fa.access_control
            ext = len([x for x in fa.calls if x.kind.is_external])
            writes = sorted({w.var.name for w in fa.state_writes})
            line = f"  {'ƒ' if fn.kind != 'modifier' else 'μ'} {fn.signature}"
            if attrs:
                line += f"  [{' '.join(attrs)}]"
            click.echo(line)
            details = []
            if guard:
                details.append(f"guard: {guard}")
            if ext:
                details.append(f"external calls: {ext}")
            if writes:
                details.append(f"writes: {', '.join(writes)}")
            if details:
                click.echo(f"      {' · '.join(details)}")
        click.echo()
    for path, err in project.parse_errors:
        click.echo(f"warning: {path}:{err}", err=True)


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--external/--no-external", default=True, help="Include external calls as dashed edges.")
def callgraph(paths, external: bool) -> None:
    """Emit a Graphviz DOT call graph (pipe into `dot -Tsvg`)."""
    project = _load_project(paths)
    cache = AnalysisCache(project)
    lines = ["digraph chainmail {", '  rankdir=LR; node [shape=box, fontname="Helvetica", fontsize=10];']
    ext_nodes: set[str] = set()
    for info in project.iter_contracts():
        if info.kind == "interface":
            continue
        lines.append(f'  subgraph "cluster_{info.name}" {{ label="{info.name}"; style=rounded;')
        for fn in info.contract.functions + info.contract.modifiers:
            nid = f"{info.name}.{fn.name or fn.kind}"
            color = "#d1452b" if fn.is_public_entry and not fn.is_view else "#2b7bb9" if fn.is_public_entry else "#6b7385"
            lines.append(f'    "{nid}" [label="{fn.name or fn.kind}", color="{color}"];')
        lines.append("  }")
        for fn in info.contract.functions + info.contract.modifiers:
            src = f"{info.name}.{fn.name or fn.kind}"
            fa = cache.get(fn, info)
            for mod in fn.modifier_names:
                if info.modifier(mod):
                    lines.append(f'  "{src}" -> "{info.name}.{mod}" [style=dotted];')
            for call in fa.calls:
                if call.kind is CallKind.INTERNAL and call.resolved is not None:
                    lines.append(f'  "{src}" -> "{call.resolved.contract_name or info.name}.{call.resolved.name}";')
                elif external and call.kind.is_external:
                    target = f"ext:{call.name}"
                    ext_nodes.add(target)
                    lines.append(f'  "{src}" -> "{target}" [style=dashed, color="#c98a00"];')
    for n in sorted(ext_nodes):
        lines.append(f'  "{n}" [shape=ellipse, color="#c98a00", label="{n[4:]}()"];')
    lines.append("}")
    click.echo("\n".join(lines))


if __name__ == "__main__":  # pragma: no cover
    main()
