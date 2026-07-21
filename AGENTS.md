# Caushell Agent Rules

## Architecture Discipline

- Do not use "temporary", "just to get it running", or knowingly low-quality structure as an intermediate step if it creates architectural debt that will need cleanup later.
- Prefer correct foundational design from the start, especially for core abstractions, data models, module boundaries, and extension points.
- If a shortcut would make the current step easier but would leave behind messy structure, hidden coupling, broad compatibility layers, monolithic files, or misleading abstractions, do not take that shortcut.
- When bootstrapping a new subsystem, keep the implementation minimal, but the structure must still be production-worthy and aligned with the intended long-term architecture.
- If the only fast path is architecturally dirty, stop and redesign the step instead of shipping a "run first, fix later" solution.
