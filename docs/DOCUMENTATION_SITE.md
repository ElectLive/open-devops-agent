# Documentation website

The documentation website uses MkDocs and the existing Markdown guides as its
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
