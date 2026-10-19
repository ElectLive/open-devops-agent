---
title: Documentation
hide:
  - navigation
  - toc
---

<div class="docs-hero" markdown="1">

<div class="docs-hero-copy" markdown="1">

<p class="docs-eyebrow">Open DevOps Agent / Documentation</p>

# Set up, connect, and troubleshoot.

Install the agent, configure your integrations, and follow the guides for
reviewing incidents, controlling changes, and checking the results in your environment.

<div class="docs-actions" markdown="1">

[Start local setup](GETTING_STARTED.md){ .docs-button .docs-button-primary }
[Browse API reference](API_REFERENCE.md){ .docs-button .docs-button-secondary }

</div>

<p class="docs-hero-note">Python 3.10 or later · Local, Docker, and cloud deployment guides</p>

</div>

<div class="docs-hero-panel" markdown="1">

<p class="docs-panel-label">A practical starting point</p>

### Start with a local environment

From the cloned repository, create a local environment before connecting the agent to infrastructure.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Keep `AUTO_APPLY=false` while reviewing proposed actions.

[Read the configuration steps](GETTING_STARTED.md#3-configure-api-keys)

</div>

</div>

## Choose your next task

<div class="docs-grid" markdown="1">

<div class="docs-card" markdown="1">

### Install and configure

Set up a local environment, configure credentials and confirm that the API is running.

[Start the local setup](GETTING_STARTED.md){ .docs-card-link }

[Package and Docker builds](BUILD_AND_USAGE.md) · [Usage reference](../usage-readme.md)

</div>

<div class="docs-card" markdown="1">

### Deploy the service

Choose a deployment model and configure the service for your environment.

[Read the deployment guide](DEPLOYMENT.md){ .docs-card-link }

[Centralized deployment](CENTRALIZED_DEPLOYMENT.md) · [Organization rollout](ORGANIZATIONAL_GUIDE.md)

</div>

<div class="docs-card" markdown="1">

### Connect platforms

Check the support matrix and find the configuration for your CI/CD or cloud platform.

[Check platform support](PLATFORM_SUPPORT.md){ .docs-card-link }

[Platform configuration](MULTI_PLATFORM_GUIDE.md) · [Grafana and Prometheus](GRAFANA_PROMETHEUS.md) · [Deployment examples](USE_CASES_GCP_GITLAB_AND_AWS_BAMBOO.md)

</div>

<div class="docs-card" markdown="1">

### Use and test the API

Look up endpoints, webhook signatures, organization scoping and request examples.

[Open the API reference](API_REFERENCE.md){ .docs-card-link }

[Postman and curl tests](API_TESTING.md) · [EC2 and Docker checks](E2E_EC2_DOCKER_TEST.md)

</div>

<div class="docs-card" markdown="1">

### Review safety controls

Understand operation restrictions, approval requirements and the documented limits of the system.

[Review safety guarantees](../SECURITY_GUARANTEES.md){ .docs-card-link }

[Security policy](SECURITY_POLICY.md) · [Coverage gaps](COVERAGE_GAPS.md)

</div>

<div class="docs-card" markdown="1">

### Investigate and extend

Follow escalation setup, inspect the architecture or prepare a contribution.

[Configure escalation](ESCALATION.md){ .docs-card-link }

[Architecture](../ARCHITECTURE.md) · [Contributing](../CONTRIBUTING.md)

</div>

</div>

## Before running against infrastructure

Start with `AUTO_APPLY=false`, use credentials scoped to the systems you intend
to connect, and review the safety documentation. Platform support and available
operations vary; use the [support matrix](PLATFORM_SUPPORT.md) and
[coverage gaps](COVERAGE_GAPS.md) to check the behaviour you need.

## How these guides are organized

Use the topic navigation for setup, deployment, API and security documentation.
Long pages have an on-page contents list, and search covers the complete guide
collection. Code blocks provide a copy control for commands and configuration.

The **Project notes** section preserves earlier status reports and design
summaries. Use the current support matrix and source code to verify the claims in those notes.

To update or publish the website, follow the
[documentation maintenance guide](DOCUMENTATION_SITE.md).
