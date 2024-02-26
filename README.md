# Kubenumerate

Enumerate your Kubernetes cluster with just 1 command :eyes:

## Motivation

- Concerned about your Kubernetes cluster's security?  
- You're going to use kubeaudit, kube-bench and trivy anyway?
- Do you want all done for you with one lazy command and exported to excel?

Enter kubenumerate!

## Usage

    ┌──(root㉿SubtleLabs)-[~]
    └─# kubenumerate -h

    Kubenumerate - Scan your whole current context with just 1 command
         Version: v1.0.2
          Author: 0x5ubt13
    
    usage: kubenumerate [-h] [--excel-out EXCEL_OUT] [--kubeaudit-out KUBEAUDIT_OUT] [--namespace NAMESPACE] [--output OUTPUT] [--trivy-file TRIVY_FILE] [--verbosity VERBOSITY]
    
    Uses local kubeconfig file to launch kubeaudit, kube-bench, kubectl and trivy and parses all useful output to excel.
    
    options:
      -h, --help            show this help message and exit
      --excel-out EXCEL_OUT, -e EXCEL_OUT
                            Select a different name for your excel file. Default: /tmp/kubenumerate_out/kubenumerate_results_v1_0.xlsx
      --kubeaudit-out KUBEAUDIT_OUT, -a KUBEAUDIT_OUT
                            Select an input kubeaudit json file to parse instead of running kubeaudit using your kubeconfig file
      --namespace NAMESPACE, -n NAMESPACE
                            Select a specific namespace to test, if your scope is restricted. Default: -A
      --output OUTPUT, -o OUTPUT
                            Select a different folder for all the output (default /tmp/kubenumerate_out/)
      --trivy-file TRIVY_FILE, -t TRIVY_FILE
                            Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file
      --verbosity VERBOSITY, -v VERBOSITY
                            Select a verbosity level. (0 = quiet | default = 1 | verbose/debug = 2)


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
    printf "Removing container ->"; docker rm kubenumerate
    rm /tmp/config

If you want to build the image yourself, simply clone the repo, `cd` into it, make any changes you want to the source code and use `docker build`:

    git clone https://github.com/0x5ubt13/kubenumerate.git
    cd kubenumerate
    docker build -t gagarter/kubenumerate .

## To Do

- [x] Add verbose flag
- [x] Containerise
- [ ] Offer the user to install all reqs for them
- [ ] Clear all TODOs
