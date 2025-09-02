# Kubenumerate

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
	          By 0x5ubt13 v2.0.0

    usage: kubenumerate.py [-h] [--cheatsheet] [--dry-run] [--excel-out EXCEL_OUT] [--kubeconfig KUBECONFIG][--namespace NAMESPACE] [--output OUTPUT] [--trivy-file TRIVY_FILE] [--verbosity VERBOSITY]

    Uses local kubeconfig file to launch kubectl, trivy and KubiScan and parses all useful output to excel.
    
    options:
      -h, --help            show this help message and exit
      --cheatsheet, -c      Print commands to extract info from the cluster and work offline
      --dry-run, -d         Don't contact the Kubernetes API - do all work locally
      --excel-out EXCEL_OUT, -e EXCEL_OUT
                            Select a different name for your excel file. Default: kubenumerate_results_v1_0.xlsx
      --kubeconfig KUBECONFIG, -k KUBECONFIG
                            Select a specific Kubeconfig file you want to use
      --namespace NAMESPACE, -n NAMESPACE
                            Select a specific namespace to test, if your scope is restricted. Default: -A
      --output OUTPUT, -o OUTPUT
                            Select a different folder for all the output. Default: '/tmp/kubenumerate_out/'
      --trivy-file TRIVY_FILE, -t TRIVY_FILE
                            Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file
      --verbosity VERBOSITY, -v VERBOSITY
                            Select a verbosity level. (0 = quiet | 1 = default | 2 = verbose/debug)
    
## Installation (containerised version available below if you don't want to keep this on your system)

    git clone https://github.com/0x5ubt13/kubenumerate.git && \ 
    cd kubenumerate && \ 
    python3 -m venv venv && \ 
    source venv/bin/activate && \ 
    pip install -r requirements.txt && \ 
    echo '#!/bin/bash\nsource "$(pwd)/venv/bin/activate"\nexec python3 "$(pwd)/kubenumerate.py" "$@"' > kubenumerate.sh && \ 
    chmod +x kubenumerate.sh && \ 
    sudo ln -s "$(pwd)/kubenumerate.sh" /usr/local/bin/kubenumerate

## Examples

Run using your kubeconfig file (simply call the script!)
    
    kubenumerate

Run locally using extracted pods.json (no kubeconfig file needed)

    kubenumerate -o ./kubenumerate_out/dev_cluster -t pods-dev.json --dry-run

## Containerised version

If you don't want to install everything in your system, a containerised version is available at [Docker Hub: gagarter/kubenumerate](https://hub.docker.com/r/gagarter/kubenumerate).
You will need to mount your `kubeconfig` file inside the container, then mount the desired output folder inside the container, and after running, it will dump all the output in the mounted folder. All this can be done with the following example commands:

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

    # Create folder and prepare kubeconfig file and out directory
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
