"""
TimeCodeSecurity (TCS) - Vector C Import & Distribution Directional Resolvers.
Provides explicit forward and reverse resolution between distribution package names
and AST import root namespaces.
"""

from typing import Optional, Set, Tuple
from sca_reachability.contracts import (
    ImportDistributionResult,
    ImportNamespaceResult,
)
from sca_reachability.dist_import_map import (
    get_curated_imports_for_dist,
    get_curated_dists_for_import,
)


def resolve_import_to_distributions(
    import_root: str,
    target_env: Optional[str] = None,
    declared_distributions: Optional[Set[str]] = None,
) -> ImportDistributionResult:
    """
    Reverse Attribution: Maps an AST import root (e.g. 'PIL', 'dateutil', 'vulnlib')
    to its providing distribution package name(s) (e.g. 'pillow', 'python-dateutil', 'vulnlib').

    Evidence Hierarchy:
    1. VERIFIED_STATIC_CURATED_MAPPING (STATIC_METADATA) - definitive
    2. TARGET_ENVIRONMENT_METADATA (exact match against declared distributions or target environment) - definitive
    3. NORMALIZED_HEURISTIC (NONE) - non-definitive
    4. UNRESOLVED
    """
    clean_root = import_root.strip()
    norm_root = clean_root.lower().replace("_", "-")

    # Step 1: Curated bidirectional tables (pillow -> PIL, python-dateutil -> dateutil, etc.)
    curated = get_curated_dists_for_import(clean_root) or get_curated_dists_for_import(norm_root)
    if curated:
        # Step 4: 1-to-many guard on curated mapping
        if len(curated) > 1:
            return ImportDistributionResult(
                import_root=clean_root,
                distribution_names=curated,
                evidence_source="VERIFIED_STATIC_CURATED_MAPPING",
                environment_scope="STATIC_METADATA",
                is_definitive=False,
                limitations=(f"Ambiguous import root '{clean_root}' maps to multiple distributions: {', '.join(curated)}",)
            )
        return ImportDistributionResult(
            import_root=clean_root,
            distribution_names=curated,
            evidence_source="VERIFIED_STATIC_CURATED_MAPPING",
            environment_scope="STATIC_METADATA",
            is_definitive=True,
            limitations=()
        )

    # Step 2: Exact string match with declared distributions
    if declared_distributions:
        decl_exact = {d for d in declared_distributions if d == clean_root}
        if decl_exact:
            d_name = next(iter(decl_exact))
            return ImportDistributionResult(
                import_root=clean_root,
                distribution_names=(d_name,),
                evidence_source="TARGET_ENVIRONMENT_METADATA",
                environment_scope="TARGET_ENVIRONMENT",
                is_definitive=True,
                limitations=()
            )

        # Check PEP 503 normalized declared distributions
        decl_norm = {d for d in declared_distributions if d.lower().replace("_", "-") == norm_root}
        if len(decl_norm) == 1:
            d_name = next(iter(decl_norm))
            # If the only difference was hyphen vs underscore (e.g. my-weird-pkg vs my_weird_pkg)
            if d_name != clean_root and ("_" in clean_root or "-" in d_name):
                # Step 3: Heuristic fallback
                return ImportDistributionResult(
                    import_root=clean_root,
                    distribution_names=(d_name,),
                    evidence_source="NORMALIZED_HEURISTIC",
                    environment_scope="NONE",
                    is_definitive=False,
                    limitations=("Import namespace mapping uses non-definitive heuristic normalization; PROVEN_STATIC attribution not possible",)
                )
            return ImportDistributionResult(
                import_root=clean_root,
                distribution_names=(d_name,),
                evidence_source="TARGET_ENVIRONMENT_METADATA",
                environment_scope="TARGET_ENVIRONMENT",
                is_definitive=True,
                limitations=()
            )
        elif len(decl_norm) > 1:
            # Step 4: 1-to-many ambiguity guard
            return ImportDistributionResult(
                import_root=clean_root,
                distribution_names=tuple(sorted(decl_norm)),
                evidence_source="TARGET_ENVIRONMENT_METADATA",
                environment_scope="TARGET_ENVIRONMENT",
                is_definitive=False,
                limitations=(f"Ambiguous import root '{clean_root}' maps to multiple declared distributions: {', '.join(sorted(decl_norm))}",)
            )

    # Default fallback: If import_root looks like a standard package without declared context
    if "_" in clean_root:
        hyphenated = clean_root.replace("_", "-")
        return ImportDistributionResult(
            import_root=clean_root,
            distribution_names=(hyphenated,),
            evidence_source="NORMALIZED_HEURISTIC",
            environment_scope="NONE",
            is_definitive=False,
            limitations=("Import namespace mapping uses non-definitive heuristic normalization; PROVEN_STATIC attribution not possible",)
        )

    # Clean unhyphenated name default: without declared context, return honest heuristic
    return ImportDistributionResult(
        import_root=clean_root,
        distribution_names=(clean_root,),
        evidence_source="NORMALIZED_HEURISTIC",
        environment_scope="NONE",
        is_definitive=False,
        limitations=("Import namespace mapping uses non-definitive heuristic normalization; PROVEN_STATIC attribution not possible",)
    )


def resolve_distribution_to_imports(
    dist: str,
    target_env: Optional[str] = None,
) -> ImportNamespaceResult:
    """
    Forward Resolution: Maps a distribution package name (e.g. 'pillow', 'vulnlib')
    to its import namespace root(s) (e.g. ('PIL',), ('vulnlib',)).
    """
    clean_dist = dist.strip()
    curated = get_curated_imports_for_dist(clean_dist)
    if curated:
        return ImportNamespaceResult(
            distribution_name=clean_dist,
            import_roots=curated,
            evidence_source="VERIFIED_STATIC_CURATED_MAPPING",
            environment_scope="STATIC_METADATA",
            is_definitive=True,
            limitations=()
        )

    # Standard normalization: replace hyphens with underscores
    import_root = clean_dist.lower().replace("-", "_")
    if target_env:
        return ImportNamespaceResult(
            distribution_name=clean_dist,
            import_roots=(import_root,),
            evidence_source="TARGET_ENVIRONMENT_METADATA",
            environment_scope="TARGET_ENVIRONMENT",
            is_definitive=True,
            limitations=()
        )

    return ImportNamespaceResult(
        distribution_name=clean_dist,
        import_roots=(import_root,),
        evidence_source="NORMALIZED_HEURISTIC",
        environment_scope="NONE",
        is_definitive=False,
        limitations=("Import namespace mapping uses non-definitive heuristic normalization; PROVEN_STATIC attribution not possible",)
    )

