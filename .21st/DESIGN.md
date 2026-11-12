# Nanashi Installer

Four stages: explicit iPhone selection, Apple authentication, verified AltStore preparation, phone handoff. The desktop result means AltStore is installed and its pairing file transferred; it does not mean Nanashi is installed or that Apple authentication on the phone succeeded.

Reuse the existing Nanashi web adaptations of Glass Card by @educalvolpz (21st component 28259) and Glass Button by @jahed (4922). Color and spacing tokens live in src/Nanashi.css; there is no new visual or motion runtime. No new 21st component retrieval is claimed: the catalogue search returned 503 during this work.

Use native semantic controls, visible keyboard focus, 44-point targets and reduced-motion support. Keep credentials transient and show authentication fields only inside the native app. Error copy names the required action without presenting dependency response bodies. No downloaded installer may be replaced by an invented URL.

References and licensing boundaries are documented in README.md.
