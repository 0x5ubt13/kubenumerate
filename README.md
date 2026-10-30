# Kubenumerate

<p align="center">
  <a href="https://github.com/0x5ubt13/kubenumerate/actions/workflows/ci-cd.yml"><img src="https://github.com/0x5ubt13/kubenumerate/actions/workflows/ci-cd.yml/badge.svg" alt="CI/CD"></a>
  <a href="https://pypi.org/project/kubenumerate/"><img src="https://img.shields.io/pypi/v/kubenumerate?logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://pypi.org/project/kubenumerate/"><img src="https://img.shields.io/pypi/pyversions/kubenumerate?logo=python&logoColor=white" alt="Python versions"></a>
  <a href="https://hub.docker.com/r/gagarter/kubenumerate"><img src="https://img.shields.io/docker/pulls/gagarter/kubenumerate?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPLv3"></a>
  <a href="https://github.com/0x5ubt13/kubenumerate/releases"><img src="https://img.shields.io/github/v/release/0x5ubt13/kubenumerate?logo=github" alt="Release"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"></a>
  <a href="https://github.com/PyCQA/bandit"><img src="https://img.shields.io/badge/security-bandit-yellow.svg" alt="Security: bandit"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/0x5ubt13/kubenumerate"><img src="https://api.securityscorecards.dev/projects/github.com/0x5ubt13/kubenumerate/badge" alt="OpenSSF Scorecard"></a>
</p>

Enumerate your target Kubernetes cluster with just 1 command! :eyes:

## Motivation

- Concerned about your Kubernetes cluster's security?  
- Are you going to use tools like kubeaudit, kube-bench, and trivy anyway?
- Do you want all done for you with one lazy command and exported to excel?

Enter kubenumerate!

With just 1 command it will locate or install (with permission) all the necessary tools, enumerate the whole current context, spit out a spreadsheet containing any juicy info and raise some found issues to the CLI. A handy containerised version is released in case you don't want to pollute the system with access to the target cluster's Kubernetes API with these tools, more info below in the containerised version section.

Currently included tools:
- Kubeaudit (installing latest from brew cask)
- Kube-bench (installing latest release from [GitHub: aquasecurity/kube-bench - releases](https://github.com/aquasecurity/kube-bench/releases))
- Kubectl (installing latest from brew cask)
- Trivy (installing latest from brew cask)
- KubiScan (installing latest release from [GitHub: cyberark/KubiScan - releases](https://github.com/cyberark/KubiScan/releases))
- ExtensiveRoleCheck.py (custom version included in the repo, thanks to [PalindromeLabs' fork](https://github.com/PalindromeLabs/kubernetes-rbac-audit) from the original [CyberArk's file](https://github.com/cyberark/kubernetes-rbac-audit)) 
- oc, the OpenShift CLI (only with `--openshift`; not auto-installed)

## Usage

    ┌──(subtle㉿SubtleLabs)-[~]
    └─# kubenumerate -h

                 +-----+  1. -----
                /     /|  2. -----
               +-----+ |  3. -----
               |     | +  4. -----
               |     |/  5. -----
               +-----+  6. -----
	             Kubenumerate
	          By 0x5ubt13 v2.0.3

    usage: kubenumerate.py [-h] [--cheatsheet] [--dry-run] [--excel-out EXCEL_OUT] [--files FILES] [--kubeconfig KUBECONFIG]
                       [--namespace NAMESPACE] [--output OUTPUT] [--trivy-file TRIVY_FILE] [--verbosity VERBOSITY]
                       [--skip-summary] [--summary-output SUMMARY_OUTPUT] [--openshift]

    Uses local kubeconfig file to launch kubectl, trivy and KubiScan and parses all useful output to excel.

    options:
    -h, --help              show this help message and exit
    --cheatsheet, -c        Print commands to extract info from the cluster and work offline
    --dry-run, -d           Don't contact the Kubernetes API - do all work locally
    --excel-out EXCEL_OUT, -e EXCEL_OUT
                            Select a different name for your excel file. Default: kubenumerate_results_v1_0.xlsx
    --files FILES, -f FILES
                            Instruct Kubenumerate to use an already generated kubectl_output directory with all the necessary files to work
                            offline (pods.json, deployments.json, etc). Forces --dry-run mode.
    --kubeconfig KUBECONFIG, -k KUBECONFIG
                            Select a specific Kubeconfig file you want to use
    --namespace NAMESPACE, --project NAMESPACE, -n NAMESPACE
                            Select a namespace or OpenShift project to test. Repeat the flag to test several. Default: all namespaces
    --output OUTPUT, -o OUTPUT
                            Select a different directory for all the output. Default: '/tmp/kubenumerate_out/'
    --trivy-file TRIVY_FILE, -t TRIVY_FILE
                            Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file
    --verbosity VERBOSITY, -v VERBOSITY
                            Select a verbosity level. (0 = quiet | 1 = default | 2 = verbose/debug)
    --skip-summary, -s      Skip generating the summary table in Microsoft Word format (generated by default)
    --summary-output SUMMARY_OUTPUT
                            Specify the path for the summary Word document. Default: {output_dir}/kubenumerate_summary.docx
    --openshift, -O         Audit an OpenShift cluster: use the oc CLI instead of kubectl and add OpenShift checks
                            (SecurityContextConstraints, Routes). Needs oc in your PATH unless --dry-run or --files is used
    
## Installation (pipx ✨)

    pipx install kubenumerate

## Installation (from source)

    git clone https://github.com/0x5ubt13/kubenumerate.git && \ 
    cd kubenumerate && \ 
    python3 -m venv venv && \ 
    source venv/bin/activate && \ 
    python -m pip install . && \ 
    kubenumerate -h

Note: kubenumerate orchestrates external tools such as kubectl, kubeaudit, kube-bench, oc, trivy, kubiscan, jq, and wget.
When you run it, it can prompt to install missing tools, but you can also install them manually beforehand.

## Examples

Run using your kubeconfig file (simply call the script!)
    
    kubenumerate

Run locally using extracted pods.json (no kubeconfig file needed)

    kubenumerate -o ./kubenumerate_out/dev_cluster -t pods-dev.json --dry-run

Skip the summary table generation (only generate Excel)

    kubenumerate --skip-summary

Specify custom path for summary document

    kubenumerate --summary-output /path/to/my_report.docx

Audit an OpenShift cluster with `oc` instead of `kubectl`, adding the SCC and Route checks

    kubenumerate --openshift

Scope the run to one or more namespaces. On OpenShift a project is a namespace, so `--project` is an alias that works the same way. Only namespaced resources are read, fetched per namespace and merged. Cluster-scoped checks do not run in this mode, and the run prints a warning saying so. Resources you cannot read in a namespace are skipped.

    kubenumerate --namespace abc --namespace xyz
    kubenumerate --project team-a

## OpenShift mode

Pass `--openshift` (or `-O`) to audit an OpenShift cluster. In this mode Kubenumerate:

- Uses the `oc` CLI instead of `kubectl` for every cluster call (`oc version`, `oc api-resources`, `oc get`). `oc` is a superset of `kubectl`, so the rest of the workflow is unchanged.
- Reads the Kubernetes version from the `Kubernetes Version` line of `oc version`, not `Server Version`. On OpenShift the latter is the OCP release (4.x), which would break the version comparison.
- Adds three sheets to the Excel workbook:
  - **OpenShift - Pod SCC**: pods admitted under a permissive SecurityContextConstraints (SCC): `privileged`, `anyuid`, `hostnetwork`, `hostnetwork-v2`, `hostaccess`, `hostmount-anyuid`, `node-exporter`. Read from the `openshift.io/scc` annotation.
  - **OpenShift - SCC definitions**: SCCs that allow privileged containers, host namespaces or host paths, or run as any UID, and permissive SCCs granted to `system:authenticated`, `system:anonymous` or `system:unauthenticated`. The default `restricted-v2` SCC is granted to `system:authenticated` and is deliberately not flagged.
  - **OpenShift - Routes**: Routes with no `spec.tls` (plain HTTP) or with `insecureEdgeTerminationPolicy: Allow`.

Requirements and limits:

- `oc` must be in your `PATH`. Kubenumerate does not install it; download it from [mirror.openshift.com](https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/). It is not needed with `--dry-run` or `--files`. The containerised image ships `oc`.
- The OpenShift findings are not in the Word summary, which only covers workload controllers. Pod findings come from the annotation on the Pod object, so they appear under `Pod` rather than under the owning Deployment.
- Trivy pulls each image itself. Images in the internal registry (`image-registry.openshift-image-registry.svc`) or other private registries need credentials available to Trivy (for example `~/.docker/config.json`); images it cannot pull are skipped.
- OAuth/identity providers, cluster-wide configuration and the `kubeadmin` user are not audited.

## Project and namespace review

Selecting one or more namespaces (`--namespace`, `--project` or `-n`, repeatable) confines the run to those namespaces:

- Only namespaced resources are listed, once per namespace. Cluster-scoped kinds are not requested, so the cluster-scoped checks (ClusterRoles, ClusterRoleBindings, admission webhooks, nodes, OpenShift SCC definitions) do not run. Their sheets and Word sections are omitted, and `coverage.md` records them as *not assessed*.
- KubiScan and ExtensiveRoleCheck are not run, because they audit cluster-wide RBAC.
- Namespace objects are cluster-scoped, so each selected namespace is read by name with a single GET, never listed. That read supplies the Pod Security Admission labels.
- `kubectl version` and API discovery (`api-resources`) still run, since they describe the cluster rather than its data.
- A forbidden or failed request is never retried in a wider scope.
- Existing output files are reused, as on `main`, so an interrupted run resumes. Reuse is allowed only when the files were collected for the same scope: the run writes `.kubenumerate_scope.json` into the output directory, and a run with a different scope, or with files but no marker, refuses and exits. Use a new `--output` for a different scope. Reused resources are listed as `reused` in `coverage.md`.

Checks covered in this mode: Pod Security Admission labels; namespaced Roles and RoleBindings (wildcards, Secret access, pod exec, workload creation, RBAC changes, escalation, impersonation, and references to ClusterRoles, reported by reference only); service-account token automounting; Service and Ingress configuration; ResourceQuota, LimitRange, PVC and PodDisruptionBudget configuration; Pods that differ from their controller's template; and Confluent Platform custom resources (Kafka listeners, topics, components and role bindings).

These are observations of declared or observed configuration. A missing field is reported as "not set" and is not proof that no other control applies. Nothing tests runtime behaviour, and Secret values, principal names and subject names are never written to the report.

The review runs in every run. Namespace checks run in both modes; cluster-scoped checks run in cluster-wide runs only. Skip the review with `--skip-control-plane-review`. Coverage is still recorded in `coverage.md`. Trivy (image pulls and vulnerability database updates) runs by default; `--skip-trivy` turns it off, and then Trivy is not required. In a namespace run Trivy scans only the images of the selected namespaces' pods.

Every live run also writes `run_metadata.json` (tool version, UTC timestamp, platform, selected namespaces, and per-resource coverage), and `coverage.md`, a readable table of the same coverage. Offline runs (`--files`, `--dry-run`) collect nothing, so they write neither. A status of *forbidden*, *unsupported*, *not found*, *failed* or *not assessed* means the review could not see that data. It is not a clean result.

## Output

Kubenumerate generates two types of output:

### 1. Detailed Excel Workbook (Default: `kubenumerate_results_v1_0.xlsx`)

Contains detailed findings across multiple sheets:
- **AppArmor** - AppArmor profile issues
- **Automount SA** - Service account token automounting issues  
- **Capabilities** - Linux capabilities configurations
- **Deprecated API** - Deprecated Kubernetes API usage
- **Host Namespace** - Host PID/Network namespace usage
- **Limits** - Resource limits configuration
- **Mounts** - Sensitive path mounts
- **Network Policies** - Network policy configurations
- **Non Root** - RunAsNonRoot configurations
- **Privilege Escalation** - allowPrivilegeEscalation settings
- **Privileged** - Privileged containers
- **Root Filesystem** - Read-only root filesystem settings
- **Seccomp** - Seccomp profile configurations
- **Vulnerable Images** - Container images with CVEs (from Trivy)
- **PSA labels** - Pod Security Admission enforce/audit/warn labels per namespace
- **RBAC - Roles** / **RBAC - Bindings** - Risky namespaced permissions and how Roles are bound
- **Service exposure** / **Ingress TLS** - Service types, ports and selectors; Ingress hosts and TLS (configuration only)
- **Cluster RBAC - Roles** / **Cluster RBAC - Bindings** - Risky ClusterRole permissions and how ClusterRoles are bound. Roles named `system:*` are Kubernetes defaults and are not reviewed. Cluster-wide runs only
- **Admission webhooks** - Failure policy and external endpoints. Cluster-wide runs only
- **Nodes** - Kubelet version per node, and version skew across nodes. Cluster-wide runs only
- **OpenShift - SCC definitions** - Permissive SCCs. OpenShift, cluster-wide runs only
- **SA tokens** - Service-account token automounting and pod-level overrides
- **Template drift** - Pods whose security-relevant settings differ from their controller's template
- **Resource controls** - ResourceQuota, LimitRange, PVC and PodDisruptionBudget configuration
- **Confluent - Kafka** / **Confluent - Components** - Declared Confluent Platform configuration (no Secret values)
- **OpenShift - ...** - OpenShift-specific sheets (SCCs, Routes), present in `--openshift` mode

An Excel sheet is written only when it has findings. Use `--generate-empty-sheets` to write every sheet the run produces, including empty ones. Coverage is not a sheet: it is written to `coverage.md` in the output directory.

### 2. Word Summary Table (Default: `kubenumerate_summary.docx`) - **Generated Automatically**

The summary, in this order:
- **Workload controllers** - Namespace, workload, type and issues, for each workload with findings
- **Review sections** - Every observation from the review sections that ran in this mode, with namespace, kind, name, observation and recommendation

Notes at the top state what the run did not check.

**Features:**
- Excludes ephemeral Pods (shows parent controllers only)
- Intelligent ReplicaSet deduplication (avoids showing Deployment-managed ReplicaSets)
- Professional formatting with colored headers and alternating row colors
- Summary statistics at the bottom

**To skip summary generation:** Use `--skip-summary` or `-s` flag

## Containerised version

If you don't want to install everything in your system, a containerised version is available at [Docker Hub: gagarter/kubenumerate](https://hub.docker.com/r/gagarter/kubenumerate).

You will need to mount your `kubeconfig` file inside the container, along with any cloud file or env variable needed for the container to authenticate to a CSP, then mount the desired output directory inside the container, and after running, it will dump all the output in the mounted directory. 

A basic example of how can this be done:

    # Create directory and prepare kubeconfig file and out directory
    mkdir /tmp/kubenumerate_out
    cp ~/.kube/config /tmp/config
    chmod a+r /tmp/config
    chmod a+w /tmp/kubenumerate_out
    
    # Run the program
    docker run \
        --network host \
        --name kubenumerate \
        -v /tmp/config:/home/subtle/.kube/config \
        --mount type=bind,source=/tmp/kubenumerate_out,target=/tmp/kubenumerate_out \
        gagarter/kubenumerate
    
    # Clean up
    printf "Removing container -> "; docker rm kubenumerate
    rm /tmp/config

or, if you're using PowerShell on Windows:

    # Create directory and prepare kubeconfig file and out directory
    New-Item -Path "C:\tmp\kubenumerate_out" -ItemType Directory
    Copy-Item -Path "$env:USERPROFILE\.kube\config" -Destination "C:\tmp\config"
    icacls "C:\tmp\config" /grant Everyone:R
    icacls "C:\tmp\kubenumerate_out" /grant Everyone:W
    
    # Run the program
    docker run `
        --network host `
        --name kubenumerate `
        -v C:\tmp\config:/home/subtle/.kube/config `
        --mount type=bind,source=C:\tmp\kubenumerate_out,target=/tmp/kubenumerate_out `
        gagarter/kubenumerate
    
    # Clean up
    Write-Output "Removing container -> "; docker rm kubenumerate
    Remove-Item -Path "C:\tmp\config"

If you want to build the image yourself, simply clone the repo, `cd` into it, make any changes you want to the source code and use `docker build`:

    git clone https://github.com/0x5ubt13/kubenumerate.git
    cd kubenumerate
    # Edit the repo as you like, then:
    docker build -t gagarter/kubenumerate:your_custom_tag .

## Other enumeration tools you might be interested in

I developed a fully automated enumeration tool that performs infrastructure scans, which gained some traction but needs feedback, so feel free to try [GitHub - 0x5ubt13/Enumeraga](https://github.com/0x5ubt13/enumeraga) if you're going to play a CTF (single target scan) or do an infra job (subnet range scan). 

## To Do

- [x] Add verbose flag
- [x] Containerise
- [x] Offer the user to install all reqs for them
- [ ] Clear all TODOs
