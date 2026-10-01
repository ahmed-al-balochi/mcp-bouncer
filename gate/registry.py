"""Loads policy.yaml, the single source of gate rules, and refuses bad input.

load_registry returns a fully validated registry or raises PolicyConfigError.
Team overrides may only tighten; any loosening refuses the boot.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from gate.policy import Limits

DEFAULT_POLICY_FILENAME = "policy.yaml"
POLICY_PATH_ENV = "BOUNCER_POLICY"

_CLASSES = ("read", "write", "destructive")
_LITERALS: Mapping[str, Any] = {"true": True, "false": False, "null": None}

# Escalate-only ladder for classification: a team may promote
# read -> write -> destructive but never demote, the same escalation floor
# policy.py applies to annotations.
_CLASS_SEVERITY: Mapping[str, int] = {name: rank for rank, name in enumerate(_CLASSES)}

# Action restrictiveness: pass < approve < block, since each step withholds
# strictly more. A team may make an action stricter but never looser; block, the
# tightest, ranks highest.
_ACTION_RESTRICTIVENESS: Mapping[str, int] = {"pass": 0, "approve": 1, "block": 2}


class PolicyConfigError(RuntimeError):
    """policy.yaml is missing, unparsable, or does not describe a valid policy."""


@dataclass(frozen=True)
class TeamView:
    """A single team's effective, already-tightened rules.

    Precomputed at boot so the request path is a dict lookup and loosening is
    caught first. Shaped like the baseline so the pure engine cannot tell apart.
    """

    patterns: Mapping[str, str]
    limits: Limits


@dataclass(frozen=True)
class Registry:
    """Validated rules, in the shape the pure policy functions expect."""

    patterns: Mapping[str, str]
    limits: Limits
    source: Path
    teams: Mapping[str, TeamView]

    def for_team(self, team: str | None) -> TeamView:
        """Return the effective view for a team, falling back to the baseline.

        A team with no override runs on the baseline, the loosest the gate
        applies. The unknown case only matters for the anonymous local run.
        """
        if team is not None and team in self.teams:
            return self.teams[team]
        return TeamView(patterns=self.patterns, limits=self.limits)


def default_policy_path() -> Path:
    override = os.environ.get(POLICY_PATH_ENV)
    if override:
        return Path(override)
    return Path.cwd() / DEFAULT_POLICY_FILENAME


def known_teams(registry: Registry) -> frozenset[str]:
    """The set of team names the policy defines, for identity validation at boot."""
    return frozenset(registry.teams)


def load_registry(policy_path: str | os.PathLike[str] | None = None) -> Registry:
    resolved = Path(policy_path) if policy_path is not None else default_policy_path()
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyConfigError(f"cannot read policy file {resolved}: {error}") from error

    document = _model_validate_or_raise(parse_policy_yaml(text), resolved)
    baseline_patterns = MappingProxyType(dict(document.tools))
    baseline_limits = Limits(
        destructive_per_hour=document.limits.destructive_per_hour,
        approval_ttl_minutes=document.limits.approval_ttl_minutes,
        actions=MappingProxyType(dict(document.actions)),
        unclassified_action=document.defaults.unclassified,
    )
    teams = _build_team_views(document, baseline_patterns, baseline_limits, resolved)
    return Registry(
        patterns=baseline_patterns,
        limits=baseline_limits,
        source=resolved,
        teams=teams,
    )


def _build_team_views(
    document: "_PolicyDocument",
    baseline_patterns: Mapping[str, str],
    baseline_limits: Limits,
    source: Path,
) -> Mapping[str, TeamView]:
    """Validate every team's overrides against the baseline and freeze the result.

    Each override is checked for loosening before it is applied; the first
    loosening refuses the boot. The pure engine stays lookup-free.
    """
    views: dict[str, TeamView] = {}
    for name, override in (document.teams or {}).items():
        patterns = _tightened_patterns(name, baseline_patterns, override, source)
        limits = _tightened_limits(name, baseline_limits, override, source)
        views[name] = TeamView(
            patterns=MappingProxyType(patterns), limits=limits
        )
    return MappingProxyType(views)


def _tightened_patterns(
    team: str,
    baseline: Mapping[str, str],
    override: "_TeamOverride",
    source: Path,
) -> dict[str, str]:
    """Merge a team's tool overrides over the baseline, rejecting any loosening.

    Refuses softening a known tool's classification and naming a tool the
    baseline does not classify, which would turn the default deny into an allow.
    """
    merged = dict(baseline)
    for tool, new_class in (override.tools or {}).items():
        if tool not in baseline:
            raise PolicyConfigError(
                f"team {team!r} in {source.name} classifies {tool!r}, which the "
                "baseline does not; a team may only tighten tools the baseline "
                "already lists, never introduce one (that would loosen the "
                "default deny)"
            )
        if _CLASS_SEVERITY[new_class] < _CLASS_SEVERITY[baseline[tool]]:
            raise PolicyConfigError(
                f"team {team!r} in {source.name} loosens {tool!r} from "
                f"{baseline[tool]!r} to {new_class!r}; overrides may only raise "
                "severity (read -> write -> destructive)"
            )
        merged[tool] = new_class
    return merged


def _tightened_limits(
    team: str,
    baseline: Limits,
    override: "_TeamOverride",
    source: Path,
) -> Limits:
    """Apply a team's limit and action overrides, rejecting any loosening.

    Caps and TTL may only be lowered and each action may only move up
    pass -> approve -> block; unclassified_action stays baseline-only.
    """
    destructive_per_hour = baseline.destructive_per_hour
    if override.limits is not None and override.limits.destructive_per_hour is not None:
        candidate = override.limits.destructive_per_hour
        if candidate > baseline.destructive_per_hour:
            raise PolicyConfigError(
                f"team {team!r} in {source.name} raises destructive_per_hour from "
                f"{baseline.destructive_per_hour} to {candidate}; a team may only "
                "lower its own cap"
            )
        destructive_per_hour = candidate

    approval_ttl_minutes = baseline.approval_ttl_minutes
    if override.limits is not None and override.limits.approval_ttl_minutes is not None:
        candidate = override.limits.approval_ttl_minutes
        if candidate > baseline.approval_ttl_minutes:
            raise PolicyConfigError(
                f"team {team!r} in {source.name} raises approval_ttl_minutes from "
                f"{baseline.approval_ttl_minutes} to {candidate}; a team may only "
                "shorten its own approval window"
            )
        approval_ttl_minutes = candidate

    actions = dict(baseline.actions)
    for classification, new_action in (override.actions or {}).items():
        current = baseline.actions.get(classification)
        if current is None:
            # The baseline must classify an action before a team tightens it;
            # otherwise there is no floor to tighten from.
            raise PolicyConfigError(
                f"team {team!r} in {source.name} overrides the action for "
                f"{classification!r}, which the baseline does not define"
            )
        if _ACTION_RESTRICTIVENESS[new_action] < _ACTION_RESTRICTIVENESS[current]:
            raise PolicyConfigError(
                f"team {team!r} in {source.name} loosens the {classification!r} "
                f"action from {current!r} to {new_action!r}; a team may only make "
                "an action stricter (pass -> approve -> block)"
            )
        actions[classification] = new_action

    return Limits(
        destructive_per_hour=destructive_per_hour,
        approval_ttl_minutes=approval_ttl_minutes,
        actions=MappingProxyType(actions),
        unclassified_action=baseline.unclassified_action,
    )


def parse_policy_yaml(text: str) -> dict[str, Any]:
    """Parse the block-mapping subset of YAML that policy.yaml is written in.

    Only comments, nested block mappings and scalar leaves are supported, so an
    unexpected construct raises. The tiny grammar keeps runtime deps minimal.
    """
    root: dict[str, Any] = {}
    frames: list[tuple[int, dict[str, Any]]] = [(0, root)]
    awaiting_children: str | None = None

    for number, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line:
            raise PolicyConfigError(f"policy line {number}: tabs are not allowed")
        line = _without_comment(raw_line).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent % 2:
            raise PolicyConfigError(
                f"policy line {number}: indent must be a multiple of two spaces"
            )
        body = line.strip()
        if body.startswith("-"):
            raise PolicyConfigError(f"policy line {number}: lists are not supported")

        key, value_text = _split_entry(body, number)

        if awaiting_children is not None:
            if indent <= frames[-1][0]:
                raise PolicyConfigError(
                    f"policy line {number}: {awaiting_children!r} has no nested entries"
                )
            child: dict[str, Any] = {}
            frames[-1][1][awaiting_children] = child
            frames.append((indent, child))
            awaiting_children = None
        else:
            while len(frames) > 1 and indent < frames[-1][0]:
                frames.pop()
            if indent != frames[-1][0]:
                raise PolicyConfigError(f"policy line {number}: unexpected indentation")

        mapping = frames[-1][1]
        if key in mapping:
            raise PolicyConfigError(f"policy line {number}: duplicate key {key!r}")
        if value_text:
            mapping[key] = _scalar(value_text)
        else:
            awaiting_children = key

    if awaiting_children is not None:
        raise PolicyConfigError(f"policy key {awaiting_children!r} has no nested entries")
    return root


def _without_comment(line: str) -> str:
    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
        elif character in "\"'":
            quote = character
        elif character == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_entry(body: str, number: int) -> tuple[str, str]:
    quote = ""
    for index, character in enumerate(body):
        if quote:
            if character == quote:
                quote = ""
        elif character in "\"'":
            quote = character
        elif character == ":":
            key = _unquoted(body[:index].strip())
            if not key:
                raise PolicyConfigError(f"policy line {number}: empty key")
            return key, body[index + 1 :].strip()
    raise PolicyConfigError(f"policy line {number}: expected 'key: value'")


def _unquoted(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _scalar(text: str) -> Any:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.lower() in _LITERALS:
        return _LITERALS[text.lower()]
    try:
        return int(text)
    except ValueError:
        return text


class _Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unclassified: Literal["block"]
    annotations: Literal["escalate-only"]


class _PolicyLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destructive_per_hour: int = Field(ge=0)
    approval_ttl_minutes: int = Field(ge=1)


class _TeamLimits(BaseModel):
    """A team's limit overrides. Both optional; both may only tighten.

    Bounds match the baseline's so an override cannot be nonsensical even before
    the tighten-only check compares it to the baseline.
    """

    model_config = ConfigDict(extra="forbid")

    destructive_per_hour: int | None = Field(default=None, ge=0)
    approval_ttl_minutes: int | None = Field(default=None, ge=1)


class _TeamOverride(BaseModel):
    """One team's override block: any subset of tools, actions, and limits.

    extra="forbid" makes "a team must not change the defaults" structural:
    there is no key for them, so naming one is a validation error.
    """

    model_config = ConfigDict(extra="forbid")

    tools: dict[str, Literal["read", "write", "destructive"]] | None = None
    actions: (
        dict[
            Literal["read", "write", "destructive"],
            Literal["pass", "block", "approve"],
        ]
        | None
    ) = None
    limits: _TeamLimits | None = None


class _PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: _Defaults
    limits: _PolicyLimits
    tools: dict[str, Literal["read", "write", "destructive"]] = Field(min_length=1)
    actions: dict[
        Literal["read", "write", "destructive"],
        Literal["pass", "block", "approve"],
    ]
    teams: dict[str, _TeamOverride] | None = None

    @field_validator("actions")
    @classmethod
    def _every_class_has_an_action(
        cls, actions: dict[str, str]
    ) -> dict[str, str]:
        missing = [name for name in _CLASSES if name not in actions]
        if missing:
            raise ValueError(f"actions is missing an entry for: {', '.join(missing)}")
        return actions


def _model_validate_or_raise(document: Any, source: Path) -> _PolicyDocument:
    if not isinstance(document, dict):
        raise PolicyConfigError(f"invalid policy file {source}: expected a mapping")
    try:
        return _PolicyDocument.model_validate(document)
    except ValidationError as error:
        raise PolicyConfigError(f"invalid policy file {source}:\n{error}") from error
