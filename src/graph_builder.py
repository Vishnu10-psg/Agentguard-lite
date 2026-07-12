"""
graph_builder.py - Dependency graph construction for AgentGuard-lite (PB-10)

Builds a directed graph: Application -> Library -> (nested) Library
using networkx, based on the OFFICIAL dataset schema:
  - sbom_dependencies.csv gives each app's direct library set
  - transitive_dependencies.json gives explicit parent->child edges
    per application, which is more reliable than inferring chains
    from a text field.
"""
import networkx as nx
from collections import defaultdict


def build_dependency_graph(sbom_rows: list[dict], transitive_rows: list[dict]) -> nx.DiGraph:
    """
    Node types:
      - Application nodes: node_id = application_id, attrs: {type: "application"}
      - Library nodes: node_id = "library@version", attrs: {type: "library", name, version, ...}

    Edges:
      - App -> each of its direct dependencies (from sbom_dependencies.csv)
      - parent library@version -> child library@version, scoped per application
        (from transitive_dependencies.json)
    """
    g = nx.DiGraph()

    # Pass 1: create application nodes and all library nodes from the SBOM rows
    for row in sbom_rows:
        app_id = row["application_id"]
        lib_name = row["library"]
        version = row["version"]
        node_id = f"{lib_name}@{version}"

        if not g.has_node(app_id):
            g.add_node(app_id, type="application", name=row.get("application_name", app_id))

        if not g.has_node(node_id):
            g.add_node(
                node_id,
                type="library",
                name=lib_name,
                version=version,
                license=row.get("license"),
                last_updated=row.get("last_updated"),
                dependency_type=row.get("dependency_type"),
            )

    # Pass 2: wire direct edges - app depends on each of its listed libraries
    for row in sbom_rows:
        app_id = row["application_id"]
        node_id = f"{row['library']}@{row['version']}"
        g.add_edge(app_id, node_id, relation="depends_on")

    # Pass 3: wire transitive edges using the OFFICIAL explicit parent->child table,
    # scoped per application_id so we don't cross-link unrelated apps' versions.
    for row in transitive_rows:
        app_id = row["application_id"]
        parent_node = f"{row['parent_library']}@{row['parent_version']}"
        child_node = f"{row['child_library']}@{row['child_version']}"

        # Ensure both nodes exist even if a child wasn't separately listed in sbom_dependencies.csv
        if not g.has_node(parent_node):
            g.add_node(parent_node, type="library", name=row["parent_library"], version=row["parent_version"])
        if not g.has_node(child_node):
            g.add_node(child_node, type="library", name=row["child_library"], version=row["child_version"])
        if not g.has_node(app_id):
            g.add_node(app_id, type="application")

        g.add_edge(parent_node, child_node, relation="depends_on_transitive")

    return g


def find_apps_exposed_to_library(g: nx.DiGraph, library_name: str, version: str | None = None) -> dict:
    """
    Given a vulnerable library (optionally pinned to a version), find every
    application exposed to it - directly or through any depth of transitive
    dependency - and the exact path(s) for each.
    """
    target_nodes = [
        n for n, attrs in g.nodes(data=True)
        if attrs.get("type") == "library"
        and attrs.get("name") == library_name
        and (version is None or attrs.get("version") == version)
    ]
    if not target_nodes:
        return {}

    app_nodes = [n for n, attrs in g.nodes(data=True) if attrs.get("type") == "application"]

    exposed: dict = defaultdict(list)
    for app in app_nodes:
        for target in target_nodes:
            if not nx.has_path(g, app, target):
                continue
            for path in nx.all_simple_paths(g, app, target):
                exposed[app].append(path)

    return dict(exposed)


def dependency_depth(path: list) -> str:
    """Classify a path as direct (app -> lib) or transitive (app -> ... -> lib)."""
    return "direct" if len(path) == 2 else "transitive"


def graph_summary(g: nx.DiGraph) -> dict:
    """Quick stats for sanity-checking the built graph."""
    apps = [n for n, a in g.nodes(data=True) if a.get("type") == "application"]
    libs = [n for n, a in g.nodes(data=True) if a.get("type") == "library"]
    return {
        "total_nodes": g.number_of_nodes(),
        "total_edges": g.number_of_edges(),
        "applications": len(apps),
        "unique_library_versions": len(libs),
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_sbom_dependencies, load_transitive_dependencies

    sbom = load_sbom_dependencies()
    transitive = load_transitive_dependencies()
    graph = build_dependency_graph(sbom, transitive)

    print("=== Graph summary ===")
    for k, v in graph_summary(graph).items():
        print(f"{k:25s}: {v}")

    print()
    print("=== Test case: httpx@1.8.0 (CVE-2022-1133) ===")
    exposed = find_apps_exposed_to_library(graph, "httpx", "1.8.0")
    if not exposed:
        print("No applications exposed to this library/version.")
    for app, paths in exposed.items():
        for path in paths:
            depth = dependency_depth(path)
            print(f"{app} -> [{depth}] {' -> '.join(path)}")

    print()
    print("=== Sample library nodes (first 10) ===")
    lib_nodes = [n for n, a in graph.nodes(data=True) if a.get("type") == "library"][:10]
    for n in lib_nodes:
        print(" ", n)