# Lab Architecture — Preserving Compilation Context

## Why this experiment does not abstract the environment through Docker

## Design Rationale

This laboratory is intentionally designed around a native FreeBSD
environment rather than Docker, WSL2, or Docker Desktop.

The reason is methodological: this research studies compilation context
as a security variable. Therefore, the laboratory is designed to
preserve and record the operating-system, filesystem,
package-management, networking, toolchain, and runtime conditions
that participate in producing and executing the artifacts under
analysis.

Docker remains useful for deployment and controlled software
distribution. It is not, however, the appropriate abstraction for
every experiment involving legacy systems and compilation-context
integrity.

The goal is not to avoid abstraction. The goal is to avoid abstracting
away variables that are themselves part of the research question.

## Laboratory Architecture

The laboratory runs on a Dell system with FreeBSD 14+ installed
directly on bare metal.

The COBOL research environment uses a FreeBSD Jail as its primary
isolation boundary:

    zroot/jails/cobol-lab

Remote access is provided through Tailscale using a private overlay
network. The laboratory does not require inbound public port forwarding
for this remote access path.

The filesystem is managed through ZFS, allowing laboratory states
to be captured through snapshots:

    zfs snapshot zroot/jails/cobol-lab@pre-audit

## Why the Compilation Context Matters

A legacy application is not defined exclusively by its source code.
The same source code may produce different compilation outcomes,
runtime behavior, diagnostics, or observable artifacts when relevant
elements of the compilation and execution context change.

The purpose of this laboratory is not to claim that one platform is
universally superior to another. Its purpose is to retain the
variables that the research intends to observe.

A container can provide excellent reproducibility when the container
image itself defines the experimental context. In this research,
the native FreeBSD environment is itself part of the context being
examined.

## Laboratory Comparison

| Property | Native FreeBSD Laboratory | Docker on Linux | WSL2 + Docker Desktop |
|---|---|---|---|
| Primary system context | Native FreeBSD userland and kernel environment | Linux userspace packaged by image, sharing host kernel | Linux environment mediated by WSL2 |
| Isolation model | FreeBSD Jails | Container isolation with shared Linux kernel | WSL2 virtualization plus container isolation |
| Build context | Native toolchain and package environment directly observable | Image-defined userspace plus host/runtime context | WSL2 Linux context plus container/runtime layers |
| State preservation | ZFS snapshots and clones | Image layers, volumes, snapshots depending on storage backend | WSL2 virtual disk and container storage |
| Experimental purpose | Preserve and observe native FreeBSD variables | Package controlled userspace environments | Enable Linux/container workflows on Windows |

## Empirical Validation: Tailscale on FreeBSD

A package-version divergence was observed on the native FreeBSD
environment.

On the laboratory host, pkg and the Tailscale CLI can represent
version information differently: the FreeBSD package system tracks
the complete package version, including FreeBSD port revisions such
as _N, while the upstream binary reports its own application version.

A related upstream issue documents this behavior on FreeBSD: when
Tailscale's auto-update mechanism detects a newer package revision
that is not yet available through the local FreeBSD package mirror,
the daemon may repeatedly attempt an update and restart. In the
reported case, tailscale update --dry-run continued to report a
version difference while pkg upgrade reported that the installed
packages were current.

This observation is relevant to the laboratory because package
management and runtime behavior are part of the environment being
observed. It does not establish that every FreeBSD package revision
will produce repeated restarts, nor does it by itself identify the
internal version-comparison mechanism.

The observed version and package-management interaction is specific
to the FreeBSD package context examined in this laboratory. The
experiment does not claim that equivalent update or version-divergence
behavior cannot occur on other platforms.

Reference: github.com/tailscale/tailscale/issues/18136#issuecomment-5360842037

## Relationship with cobol-shield

cobol-shield and the FreeBSD laboratory operate at different layers
of the same research methodology.

cobol-shield analyzes legacy COBOL source for format-dependent,
transformation-sensitive, and other statically observable properties.
The FreeBSD laboratory provides the controlled environment in which
those artifacts can be compiled, executed, inspected, and preserved
while retaining the surrounding system context.

                 COBOL Source
                      |
          +-----------+-----------+
          v                       v
   cobol-shield             Compilation Context
   static analysis                 |
          |                        |
          |                +-------+--------+
          |                v                v
          |         Compiler / Toolchain  Runtime Environment
          |                |                |
          |                v                |
          |         Compiled Artifact       |
          |                |                |
          +----------------+----------------+
                           |
                           v
                    Observed Evidence

- cobol-shield is the analysis instrument.
- FreeBSD is the experimental environment.
- Jails provide isolation.
- ZFS provides state preservation through snapshots and clones,
  supporting reproducible laboratory workflows when combined with
  recorded toolchain versions, package manifests, configuration,
  and other experimental metadata.
- Tailscale provides controlled remote connectivity while
  remaining part of the native system context.

## Forensic Reproducibility

ZFS snapshots allow a defined laboratory state to be preserved
before an audit or experiment:

    zfs snapshot zroot/jails/cobol-lab@pre-audit-YYYY-MM-DD

This does not by itself establish complete forensic chain of custody.
It provides a concrete and auditable mechanism for preserving
laboratory state, which can be combined with hashes, logs, toolchain
versions, package manifests, and configuration records appropriate
to the experiment.

## Research Principle

Do not remove a variable from the experiment when that variable is
part of what the experiment is designed to measure.

## Research Connection

This laboratory provides the practical infrastructure for the
research described in:

Source Transformation Integrity in Legacy COBOL Systems:
A Static Analysis Approach to Detecting Format-Dependent
Semantic Divergence

DOI: 10.5281/zenodo.21974261

Reference: Tailscale Issue #18136; FreeBSD Handbook - Jails/ZFS;
DOI 10.5281/zenodo.21974261
