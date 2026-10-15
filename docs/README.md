# Open DevOps Agent documentation

Configure the agent, connect your platforms, and review how incidents move from
an incoming alert to diagnosis, approval and a recorded outcome.

<div class="docs-path" markdown="1">

**New to the project?** Start with the [local setup guide](GETTING_STARTED.md),
then check [platform support](PLATFORM_SUPPORT.md) and the
[safety guarantees](../SECURITY_GUARANTEES.md) before connecting infrastructure.

</div>

## Find the right guide

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

[Platform configuration](MULTI_PLATFORM_GUIDE.md) · [Deployment examples](USE_CASES_GCP_GITLAB_AND_AWS_BAMBOO.md)

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
summaries. Read those as project history alongside the current support matrix
and source code, rather than as release guarantees.

To update or publish the website, follow the
[documentation maintenance guide](DOCUMENTATION_SITE.md).
