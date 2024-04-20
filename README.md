# Kubenumerate

Enumerate your Kubernetes cluster with just 1 command :eyes:

## Motivation

- Concerned about your Kubernetes cluster's security?  
- Are you going to use tools like kubeaudit, kube-bench and trivy anyway?
- Do you want all done for you with one lazy command and exported to excel?

Enter kubenumerate!

## Usage

    ┌──(subtle㉿SubtleLabs)-[~]
    └─# kubenumerate -h

    __  __         __                                                 __         
    |  |/  |.--.--.|  |--.-----.-----.--.--.--------.-----.----.---.-.|  |_.-----.
    |     < |  |  ||  _  |  -__|     |  |  |        |  -__|   _|  _  ||   _|  -__|
    |__|\__||_____||_____|_____|__|__|_____|__|__|__|_____|__| |___._||____|_____|
            
    v1.0.7                                                            By 0x5ubt13

    usage: kubenumerate.py [-h] [--cheatsheet] [--dry-run] [--excel-out EXCEL_OUT] [--kubeaudit-file KUBEAUDIT_FILE]
                       [--kubeconfig KUBECONFIG] [--namespace NAMESPACE] [--output OUTPUT] [--trivy-file TRIVY_FILE]
                       [--verbosity VERBOSITY]

    Uses local kubeconfig file to launch kubeaudit, kube-bench, kubectl and trivy and parses all useful output to excel.
    
    options:
      -h, --help            show this help message and exit
      --cheatsheet, -c      Print commands to extract info from the cluster and work offline
      --dry-run, -d         Don't contact the Kubernetes API - do all work locally
      --excel-out EXCEL_OUT, -e EXCEL_OUT
                            Select a different name for your excel file. Default: kubenumerate_results_v1_0.xlsx
      --kubeaudit-file KUBEAUDIT_FILE, -f KUBEAUDIT_FILE
                            Select an input kubeaudit json file to parse instead of running kubeaudit using your
                            kubeconfig file.
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
    
## Installation

    git clone https://github.com/0x5ubt13/kubenumerate.git
    cd kubenumerate
    pip install -r requirements.txt
    chmod +x kubenumerate.py
    sudo ln -s "$(pwd)"/kubenumerate.py /usr/bin/kubenumerate # Or anywhere else in your $PATH, or add to your PATH so no sudo is involved
    kubenumerate -h

## Examples

Run using your kubeconfig file (simply call the script!)
    
    kubenumerate

Run locally using extracted kubeaudit.json and pods.json (no kubeconfig file needed)

    kubenumerate -o ./kubenumerate_out/dev_cluster -f kubeaudit-dev.json -t pods-dev.json --dry-run

## Containerised version

If you don't want to install everything in your system, a containerised version is available at [Docker Hub: gagarter/kubenumerate](https://hub.docker.com/r/gagarter/kubenumerate).
You will need to mount your `kubeconfig` file inside the container, then mount the desired output folder inside the container, and after running, it will dump all the output in the mounted folder. All this can be done with the following example commands:

    # Create folder and prepare kubeconfig file and out directory
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
