# Copyright 2021 Pants project contributors (see CONTRIBUTORS.md).
# Licensed under the Apache License, Version 2.0 (see LICENSE).

from __future__ import annotations

import logging
import zlib
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from pants.backend.java.dependency_inference.java_parser import (
    JavaSourcesBatchRequest,
    analyze_java_sources_batch,
    resolve_fallible_result_to_analysis,
)
from pants.backend.java.dependency_inference.types import JavaSourceDependencyAnalysis
from pants.backend.java.target_types import JavaSourceField
from pants.core.util_rules.source_files import SourceFilesRequest, determine_source_files
from pants.engine.fs import Digest
from pants.engine.rules import collect_rules, concurrently, implicitly, rule
from pants.engine.target import AllTargets, Targets
from pants.engine.unions import UnionRule
from pants.jvm.dependency_inference import symbol_mapper
from pants.jvm.dependency_inference.artifact_mapper import MutableTrieNode
from pants.jvm.dependency_inference.symbol_mapper import FirstPartyMappingRequest, SymbolMap
from pants.jvm.subsystems import JvmSubsystem
from pants.jvm.target_types import JvmResolveField
from pants.util.frozendict import FrozenDict
from pants.util.logging import LogLevel

logger = logging.getLogger(__name__)


class AllJavaTargets(Targets):
    pass


@rule(desc="Find all Java targets in project", level=LogLevel.DEBUG)
async def find_all_java_targets(tgts: AllTargets) -> AllJavaTargets:
    return AllJavaTargets(tgt for tgt in tgts if tgt.has_field(JavaSourceField))


@dataclass(frozen=True)
class AllJavaSourceAnalyses:
    """The analyses of the Java sources of all Java targets which could be analyzed in bulk."""

    by_file: FrozenDict[str, JavaSourceDependencyAnalysis]


_ANALYSIS_BATCHES = 8


@rule(desc="Analyze all Java sources", level=LogLevel.DEBUG)
async def analyze_all_java_sources(java_targets: AllJavaTargets) -> AllJavaSourceAnalyses:
    source_files = await concurrently(
        determine_source_files(SourceFilesRequest([target[JavaSourceField]]))
        for target in java_targets
    )
    digests: dict[str, Digest] = {}
    for files in source_files:
        if len(files.files) == 1:
            digests.setdefault(files.files[0], files.snapshot.digest)
    # Batches by a stable hash of the path, so that editing one file affects one batch.
    batches: dict[int, list[str]] = defaultdict(list)
    for path in sorted(digests):
        batches[zlib.crc32(path.encode()) % _ANALYSIS_BATCHES].append(path)
    results = await concurrently(
        analyze_java_sources_batch(
            JavaSourcesBatchRequest(tuple((path, digests[path]) for path in paths)),
            **implicitly(),
        )
        for _, paths in sorted(batches.items())
    )
    by_file: dict[str, JavaSourceDependencyAnalysis] = {}
    for result in results:
        by_file.update(result.by_file)
    return AllJavaSourceAnalyses(FrozenDict(by_file))


class FirstPartyJavaTargetsMappingRequest(FirstPartyMappingRequest):
    pass


@rule(desc="Map all first party Java targets to their packages", level=LogLevel.DEBUG)
async def map_first_party_java_targets_to_symbols(
    _: FirstPartyJavaTargetsMappingRequest,
    java_targets: AllJavaTargets,
    jvm: JvmSubsystem,
) -> SymbolMap:
    all_analyses = await analyze_all_java_sources(**implicitly())
    # Sources not analyzed in bulk are analyzed individually, which reports any failure.
    individually = [
        target
        for target in java_targets
        if target[JavaSourceField].file_path not in all_analyses.by_file
    ]
    individual_analyses = dict(
        zip(
            (target.address for target in individually),
            await concurrently(
                resolve_fallible_result_to_analysis(
                    **implicitly(SourceFilesRequest([target[JavaSourceField]]))
                )
                for target in individually
            ),
        )
    )
    source_analysis = [
        all_analyses.by_file.get(target[JavaSourceField].file_path)
        or individual_analyses[target.address]
        for target in java_targets
    ]
    address_and_analysis = zip(
        [(tgt.address, tgt[JvmResolveField].normalized_value(jvm)) for tgt in java_targets],
        source_analysis,
    )

    mapping: Mapping[str, MutableTrieNode] = defaultdict(MutableTrieNode)
    for (address, resolve), analysis in address_and_analysis:
        for top_level_type in analysis.top_level_types:
            mapping[resolve].insert(top_level_type, [address], first_party=True)

    return SymbolMap((resolve, node.frozen()) for resolve, node in mapping.items())


def rules():
    return (
        *collect_rules(),
        *symbol_mapper.rules(),
        UnionRule(FirstPartyMappingRequest, FirstPartyJavaTargetsMappingRequest),
    )
