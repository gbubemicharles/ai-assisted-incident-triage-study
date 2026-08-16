from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_FILES = (
    "severity_matrix.json",
    "incident_categories.json",
    "services.json",
    "resolver_groups.json",
    "dependencies.json",
    "ownership_map.json",
    "runbooks.json",
)


@dataclass(frozen=True)
class KnowledgeBundle:
    directory: Path
    documents: dict[str, dict[str, Any]]
    version_hash: str
    allowed_refs: frozenset[str]

    def prompt_payload(self) -> str:
        """Return deterministic compact JSON for the model prompt."""
        ordered = {name: self.documents[name] for name in sorted(self.documents)}
        return json.dumps(
            ordered,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _build_allowed_refs(documents: dict[str, dict[str, Any]]) -> frozenset[str]:
    refs: set[str] = set()

    for level in documents["severity_matrix.json"]["severity_levels"]:
        refs.add(f"KB:SEVERITY:{level['name']}")

    for category in documents["incident_categories.json"]["categories"]:
        refs.add(f"KB:{category['code']}")

    for service in documents["services.json"]["services"]:
        refs.add(f"KB:{service['id']}")

    for group in documents["resolver_groups.json"]["resolver_groups"]:
        refs.add(f"KB:{group['id']}")

    for dependency in documents["dependencies.json"]["dependencies"]:
        refs.add(
            f"KB:DEP:{dependency['dependent']}:{dependency['dependency']}"
        )

    for runbook in documents["runbooks.json"]["runbooks"]:
        refs.add(f"KB:{runbook['id']}")

    for action in documents["runbooks.json"]["common_actions"]:
        refs.add(f"KB:{action['id']}")

    return frozenset(refs)


def load_knowledge_base(directory: str | Path = "knowledge_base") -> KnowledgeBundle:
    kb_dir = Path(directory)
    if not kb_dir.exists():
        raise FileNotFoundError(f"Knowledge-base directory not found: {kb_dir}")

    documents: dict[str, dict[str, Any]] = {}
    digest = hashlib.sha256()

    for filename in REQUIRED_FILES:
        path = kb_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Required knowledge file missing: {path}")

        raw = path.read_bytes()
        digest.update(filename.encode("utf-8"))
        digest.update(raw)

        try:
            documents[filename] = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    return KnowledgeBundle(
        directory=kb_dir.resolve(),
        documents=documents,
        version_hash=digest.hexdigest(),
        allowed_refs=_build_allowed_refs(documents),
    )
