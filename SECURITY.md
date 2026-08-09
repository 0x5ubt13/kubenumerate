# Security Policy

## Supported Versions

Only the latest released version of Kubenumerate receives security updates. Please make sure you are on the most recent release before reporting an issue.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues**.

Instead, report them privately using either of the following:

- [GitHub private vulnerability reporting](https://github.com/0x5ubt13/kubenumerate/security/advisories/new) (preferred)
- Email: 5ubt13@protonmail.com

Please include as much of the following as you can:

- The type of issue and the affected component
- Steps to reproduce, or a proof of concept
- The version of Kubenumerate and the platform you are running it on
- Any impact you have already assessed

## What to Expect

- An acknowledgement of your report, usually within a few days
- An assessment of the issue and, if accepted, an indication of a fix timeline
- Credit for the discovery when the fix is released, unless you would prefer to remain anonymous

## Scope

Kubenumerate is a security auditing tool that runs against Kubernetes clusters you are authorised to test. It shells out to third-party tools such as kubectl, trivy, kube-bench and KubiScan.

Vulnerabilities in those upstream tools should be reported to their respective maintainers. Issues in how Kubenumerate invokes them, handles their output, or manages credentials and kubeconfig files are in scope here.
