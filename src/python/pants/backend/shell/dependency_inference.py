# Copyright 2021 Pants project contributors (see CONTRIBUTORS.md).
# Licensed under the Apache License, Version 2.0 (see LICENSE).

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import DefaultDict

from pants.backend.shell.lint.shellcheck.subsystem import Shellcheck
from pants.backend.shell.subsystems.shell_setup import ShellSetup
from pants.backend.shell.target_types import ShellDependenciesField, ShellSourceField
from pants.core.util_rules.external_tool import download_external_tool
from pants.engine.addresses import Address
from pants.engine.collection import DeduplicatedCollection
from pants.engine.fs import Digest, MergeDigests
from pants.engine.internals.graph import determine_explicitly_provided_dependencies, hydrate_sources
from pants.engine.intrinsics import execute_process, get_digest_contents, merge_digests
from pants.engine.platform import Platform
from pants.engine.process import Process, ProcessCacheScope
from pants.engine.rules import Rule, collect_rules, concurrently, implicitly, rule
from pants.engine.target import (
    AllTargets,
    BulkInferDependenciesRequest,
    BulkInferredDependencies,
    DependenciesRequest,
    ExplicitlyProvidedDependencies,
    ExplicitlyProvidedDependenciesRequest,
    FieldSet,
    HydrateSourcesRequest,
    InferDependenciesRequest,
    InferredDependencies,
    Targets,
)
from pants.engine.unions import UnionRule
from pants.util.frozendict import FrozenDict
from pants.util.logging import LogLevel
from pants.util.ordered_set import OrderedSet

logger = logging.getLogger(__name__)


class AllShellTargets(Targets):
    pass


@rule(desc="Find all Shell targets in project", level=LogLevel.DEBUG)
async def find_all_shell_targets(all_tgts: AllTargets) -> AllShellTargets:
    return AllShellTargets(tgt for tgt in all_tgts if tgt.has_field(ShellSourceField))


@dataclass(frozen=True)
class ShellMapping:
    """A mapping of Shell file names to their owning file address."""

    mapping: FrozenDict[str, Address]
    ambiguous_modules: FrozenDict[str, tuple[Address, ...]]

    @property
    def plain_keys(self) -> tuple[bytes, ...]:
        keys = self.__dict__.get("_plain_keys")
        if keys is None:
            keys = tuple(k.encode() for k in (*self.mapping, *self.ambiguous_modules))
            object.__setattr__(self, "_plain_keys", keys)
        return keys

    @property
    def keys_are_plain(self) -> bool:
        """Whether every key is ASCII without quote or backslash characters."""
        return all(
            key.isascii() and not any(c in key for c in "\"'\\")
            for key in (*self.mapping, *self.ambiguous_modules)
        )


@rule(desc="Creating map of Shell file names to Shell targets", level=LogLevel.DEBUG)
async def map_shell_files(tgts: AllShellTargets) -> ShellMapping:
    files_to_addresses: dict[str, Address] = {}
    files_with_multiple_owners: DefaultDict[str, set[Address]] = defaultdict(set)
    for tgt in tgts:
        fp = tgt[ShellSourceField].file_path
        if fp in files_to_addresses:
            files_with_multiple_owners[fp].update({files_to_addresses[fp], tgt.address})
        else:
            files_to_addresses[fp] = tgt.address

    # Remove files with ambiguous owners.
    for ambiguous_f in files_with_multiple_owners:
        files_to_addresses.pop(ambiguous_f)

    return ShellMapping(
        mapping=FrozenDict(sorted(files_to_addresses.items())),
        ambiguous_modules=FrozenDict(
            (k, tuple(sorted(v))) for k, v in sorted(files_with_multiple_owners.items())
        ),
    )


class ParsedShellImports(DeduplicatedCollection):
    sort_input = True


_MAY_SOURCE = re.compile(rb"source|(?:^|[\s;&|({`])\.[ \t]")


def _normalized(content: bytes) -> bytes:
    return content.replace(b"\\\n", b"").replace(b'"', b"").replace(b"'", b"").replace(b"\\", b"")


def _is_opaque(content: bytes) -> bool:
    """Whether literals in the content may be spelled in ways `_normalized` does not undo."""
    if b"$'" in content:
        return True
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _may_mention_any(content: bytes, keys: tuple[bytes, ...]) -> bool:
    """Whether any key may occur as a (possibly quoted or escaped) literal in the content."""
    if _is_opaque(content):
        return True
    normalized = _normalized(content)
    return any(key in normalized for key in keys)


@dataclass(frozen=True)
class ParseShellImportsRequest:
    digest: Digest
    fp: str


PATH_FROM_SHELLCHECK_ERROR = re.compile(r"Not following: (.+) was not specified as input")


@rule
async def parse_shell_imports(
    request: ParseShellImportsRequest, shellcheck: Shellcheck, platform: Platform
) -> ParsedShellImports:
    # We use Shellcheck to parse for us by running it against each file in isolation, which means
    # that all `source` statements will error. Then, we can extract the problematic paths from the
    # JSON output.
    # Only `source` / `.` commands produce SC1091, so files which cannot contain one need no process.
    digest_contents = await get_digest_contents(request.digest)
    if not any(_MAY_SOURCE.search(file_content.content) for file_content in digest_contents):
        return ParsedShellImports()

    downloaded_shellcheck = await download_external_tool(shellcheck.get_request(platform))

    immutable_input_key = "__shellcheck_tool"
    exe_path = os.path.join(immutable_input_key, downloaded_shellcheck.exe)

    process_result = await execute_process(
        Process(
            # NB: We do not load up `[shellcheck].{args,config}` because it would risk breaking
            # determinism of dependency inference in an unexpected way.
            [exe_path, "--format=json", request.fp],
            input_digest=request.digest,
            immutable_input_digests={immutable_input_key: downloaded_shellcheck.digest},
            description=f"Detect Shell imports for {request.fp}",
            level=LogLevel.DEBUG,
            # We expect this to always fail, but it should still be cached because the process is
            # deterministic.
            cache_scope=ProcessCacheScope.ALWAYS,
        ),
        **implicitly(),
    )

    try:
        output = json.loads(process_result.stdout)
    except json.JSONDecodeError:
        logger.error(
            f"Parsing {request.fp} for dependency inference failed because Shellcheck's output "
            f"could not be loaded as JSON. Please open a GitHub issue at "
            f"https://github.com/pantsbuild/pants/issues/new with this error message attached.\n\n"
            f"\nshellcheck version: {shellcheck.version}\n"
            f"process_result.stdout: {process_result.stdout.decode()}"
        )
        return ParsedShellImports()

    paths = set()
    for error in output:
        if not error.get("code", "") == 1091:
            continue
        msg = error.get("message", "")
        matches = PATH_FROM_SHELLCHECK_ERROR.match(msg)
        if matches:
            paths.add(matches.group(1))
        else:
            logger.error(
                f"Parsing {request.fp} for dependency inference failed because Shellcheck's error "
                f"message was not in the expected format. Please open a GitHub issue at "
                f"https://github.com/pantsbuild/pants/issues/new with this error message "
                f"attached.\n\n\nshellcheck version: {shellcheck.version}\n"
                f"error JSON entry: {error}"
            )
    return ParsedShellImports(paths)


@dataclass(frozen=True)
class ShellDependenciesInferenceFieldSet(FieldSet):
    required_fields = (ShellSourceField, ShellDependenciesField)

    source: ShellSourceField
    dependencies: ShellDependenciesField


class InferShellDependencies(InferDependenciesRequest):
    infer_from = ShellDependenciesInferenceFieldSet


@rule(desc="Inferring Shell dependencies by analyzing imports")
async def infer_shell_dependencies(
    request: InferShellDependencies, shell_mapping: ShellMapping, shell_setup: ShellSetup
) -> InferredDependencies:
    if not shell_setup.dependency_inference:
        return InferredDependencies([])

    address = request.field_set.address
    explicitly_provided_deps, hydrated_sources = await concurrently(
        determine_explicitly_provided_dependencies(
            ExplicitlyProvidedDependenciesRequest(request.field_set.dependencies), **implicitly()
        ),
        hydrate_sources(HydrateSourcesRequest(request.field_set.source), **implicitly()),
    )
    assert len(hydrated_sources.snapshot.files) == 1

    # Only paths which are keys of the mapping can become dependencies, and every path Shellcheck
    # reports is (after removing quoting) a literal in the file: so if no key occurs in the file,
    # there are no dependencies to find.
    if shell_mapping.keys_are_plain:
        (file_content,) = await get_digest_contents(hydrated_sources.snapshot.digest)
        if not _may_mention_any(file_content.content, shell_mapping.plain_keys):
            return InferredDependencies([])

    detected_imports = await parse_shell_imports(
        ParseShellImportsRequest(
            hydrated_sources.snapshot.digest, hydrated_sources.snapshot.files[0]
        ),
        **implicitly(),
    )
    return _inferred_from_imports(
        detected_imports, shell_mapping, explicitly_provided_deps, address
    )


def _inferred_from_imports(
    detected_imports: Iterable[str],
    shell_mapping: ShellMapping,
    explicitly_provided_deps: ExplicitlyProvidedDependencies,
    address: Address,
) -> InferredDependencies:
    result: OrderedSet[Address] = OrderedSet()
    for import_path in detected_imports:
        unambiguous = shell_mapping.mapping.get(import_path)
        ambiguous = shell_mapping.ambiguous_modules.get(import_path)
        if unambiguous:
            result.add(unambiguous)
        elif ambiguous:
            explicitly_provided_deps.maybe_warn_of_ambiguous_dependency_inference(
                ambiguous,
                address,
                import_reference="file",
                context=f"The target {address} sources `{import_path}`",
            )
            maybe_disambiguated = explicitly_provided_deps.disambiguated(ambiguous)
            if maybe_disambiguated:
                result.add(maybe_disambiguated)
    return InferredDependencies(sorted(result))


_MAX_SHELLCHECK_BATCH = 16


class BulkInferShellDependencies(BulkInferDependenciesRequest):
    infers = InferShellDependencies


@rule(desc="Infer Shell dependencies in bulk", level=LogLevel.DEBUG)
async def infer_shell_dependencies_bulk(
    request: BulkInferShellDependencies,
    shell_mapping: ShellMapping,
    shell_setup: ShellSetup,
    shellcheck: Shellcheck,
    platform: Platform,
) -> BulkInferredDependencies:
    field_sets = [
        field_set
        for field_set in request.field_sets
        if isinstance(field_set, ShellDependenciesInferenceFieldSet)
    ]
    if not shell_setup.dependency_inference or not shell_mapping.keys_are_plain:
        return BulkInferredDependencies(FrozenDict())

    explicit_deps, hydrated = await concurrently(
        concurrently(
            determine_explicitly_provided_dependencies(
                ExplicitlyProvidedDependenciesRequest(field_set.dependencies), **implicitly()
            )
            for field_set in field_sets
        ),
        concurrently(
            hydrate_sources(HydrateSourcesRequest(field_set.source), **implicitly())
            for field_set in field_sets
        ),
    )
    contents = await concurrently(
        get_digest_contents(sources.snapshot.digest) for sources in hydrated
    )

    results: dict[Address, InferredDependencies] = {}
    # (field set, explicit deps, path, digest, content) of files which Shellcheck must parse.
    to_check = []
    for field_set, explicit, sources, file_contents in zip(
        field_sets, explicit_deps, hydrated, contents
    ):
        if len(sources.snapshot.files) != 1 or len(file_contents) != 1:
            continue
        content = file_contents[0].content
        # As `infer_shell_dependencies` and `parse_shell_imports` decide without a process.
        if not _may_mention_any(content, shell_mapping.plain_keys) or not _MAY_SOURCE.search(
            content
        ):
            results[field_set.address] = InferredDependencies([])
            continue
        to_check.append(
            (field_set, explicit, sources.snapshot.files[0], sources.snapshot.digest, content)
        )

    # Shellcheck parses each input file separately; a file's result only changes if a file it
    # sources is also an input, and the path of such a file ends in its basename, which then
    # occurs in the (normalized) content. So files which don't mention each other's basenames can
    # share a process.
    batches: list[list] = []
    for item in sorted(to_check, key=lambda item: item[2]):
        if _is_opaque(item[4]):
            batches.append([item])
            continue
        normalized = _normalized(item[4])
        basename = os.path.basename(item[2]).encode()
        for batch in batches:
            if (
                len(batch) < _MAX_SHELLCHECK_BATCH
                and not _is_opaque(batch[0][4])
                and not any(
                    os.path.basename(other[2]).encode() in normalized
                    or basename in _normalized(other[4])
                    for other in batch
                )
            ):
                batch.append(item)
                break
        else:
            batches.append([item])

    downloaded_shellcheck = await download_external_tool(shellcheck.get_request(platform))
    immutable_input_key = "__shellcheck_tool"
    exe_path = os.path.join(immutable_input_key, downloaded_shellcheck.exe)
    batch_inputs = await concurrently(
        merge_digests(MergeDigests(item[3] for item in batch)) for batch in batches
    )
    process_results = await concurrently(
        execute_process(
            Process(
                [exe_path, "--format=json", *(item[2] for item in batch)],
                input_digest=input_digest,
                immutable_input_digests={immutable_input_key: downloaded_shellcheck.digest},
                description=f"Detect Shell imports for {len(batch)} files",
                level=LogLevel.DEBUG,
                cache_scope=ProcessCacheScope.ALWAYS,
            ),
            **implicitly(),
        )
        for batch, input_digest in zip(batches, batch_inputs)
    )
    for batch, process_result in zip(batches, process_results):
        try:
            output = json.loads(process_result.stdout)
        except json.JSONDecodeError:
            # Parse these files individually, which reports the problem.
            continue
        paths_by_file: dict[str, set[str]] = defaultdict(set)
        unexpected = False
        for error in output:
            if not error.get("code", "") == 1091:
                continue
            matches = PATH_FROM_SHELLCHECK_ERROR.match(error.get("message", ""))
            if not matches:
                unexpected = True
                break
            paths_by_file[error.get("file", "")].add(matches.group(1))
        if unexpected:
            continue
        for field_set, explicit, path, _, _ in batch:
            results[field_set.address] = _inferred_from_imports(
                sorted(paths_by_file.get(path, ())), shell_mapping, explicit, field_set.address
            )
    return BulkInferredDependencies(FrozenDict(results))


def rules() -> Iterable[Rule | UnionRule]:
    return (
        *collect_rules(),
        UnionRule(InferDependenciesRequest, InferShellDependencies),
        UnionRule(BulkInferDependenciesRequest, BulkInferShellDependencies),
    )
