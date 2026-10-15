# Documentation website

The documentation website uses MkDocs with the Material theme and the existing Markdown guides as its
source. Root-level guides are included during the build without maintaining
duplicate copies. Search and topic navigation are generated automatically.

## Local development

Create a virtual environment and install the documentation dependencies from the
repository root before previewing the website.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-docs.txt
mkdocs serve
```

On Windows, activate the environment with `.venv\Scripts\activate` instead.
Open the local address printed by MkDocs to review your changes.

```bash
mkdocs build --strict
python scripts/check_docs_links.py
```

The strict build writes the generated website to `site/`, which is excluded from
version control. Source-code and configuration links point back to GitHub rather
than copying those files into the website.

## GitHub Pages deployment

A repository administrator must select **Settings > Pages > Build and deployment >
Source > GitHub Actions** before the first deployment. Merge the documentation
workflow, then run **Documentation** from the Actions tab or push a documentation
change to `main`. Any configured environment approval remains a maintainer step.

The intended public address is
<https://open-devops-agent.github.io/open-devops-agent/> once Pages is enabled and
the first deployment succeeds. The address is not evidence of a live deployment.

Pull requests build and validate documentation without deploying it. Publication
runs only from the upstream repository's `main` branch, using the `github-pages`
environment. Documentation dependencies are separate from application dependencies.

## Updating the documentation

Edit the existing Markdown source files and update `mkdocs.yml` when adding a new
navigation entry. Keep local Markdown links relative so they remain useful when
browsing GitHub. The build hook maps links to published guides and sends links to
repository files back to GitHub. Run the strict build before submitting a change.

## Content and design conventions

Write task-focused instructions with concrete prerequisites, commands and expected
results. Keep configuration examples and API details available from the topic
navigation. Avoid time-to-completion promises, promotional slogans and claims of
production readiness that are not supported by current evidence. Mark historical
status summaries as project notes rather than current feature guarantees.

The theme uses local system fonts, topic tabs, section navigation, an on-page
contents list, search and code-copy controls. The home page becomes a single
column on narrow screens. Keep colours and spacing in
`assets/stylesheets/documentation.css`, preserve visible keyboard focus, and
respect reduced-motion preferences when changing the design.

## Motion and interaction

Instant navigation keeps the documentation shell available between guide pages.
A short content entrance, clear hover and focus states, smooth anchor scrolling,
and a reading-progress line provide feedback while browsing. The progress line
tracks the current page and resets when navigation changes the content.

Reduced-motion preferences disable entrance animations, animated transitions, and
smooth scrolling. Content remains visible when JavaScript is unavailable, and
all guide links use standard URLs that work with normal page navigation.

## Architecture diagrams

Architecture diagrams use fenced `mermaid` blocks in the existing Markdown
sources. Material renders those blocks in the browser and adapts their colours
to the documentation theme. This includes the project overview, incident
processing, request sequence, access boundaries and credential provisioning.

Give each diagram an `accTitle` and `accDescr` so its purpose and relationships
are described in the source. Wide diagrams appear in labelled, focusable scroll
regions; use the arrow keys or horizontal scrolling to inspect their labels on
narrow screens. Keep explanatory text beside each diagram so the main workflow
remains understandable without the rendered graphic.

The theme loads Mermaid from its public CDN when a diagram page opens. A local
Markdown preview without Mermaid support displays the editable diagram source.
The strict documentation build validates Markdown links, while browser review
is required to confirm Mermaid rendering after a diagram changes.
