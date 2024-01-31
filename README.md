# kubenumerate

Enumerate your Kubernetes cluster with just 1 command :eyes:

## Motivation

- Concerned about your Kubernetes cluster's security?  
- You're going to use kubeaudit, kube-bench and trivy anyway?
- Do you want all done for you with one lazy command and exported to excel?

Enter kubenumerate!

## Usage

    ┌──(root㉿SubtleLabs)-[~]
    └─# kubenumerate.py -h
    usage: kubenumerate.py [-h] [--excel-out EXCEL_OUT] [--kubeaudit-out KUBEAUDIT_OUT] [--trivy-file TRIVY_FILE] [--output OUTPUT]
    
    Uses local kubeconfig file to launch kubeaudit, kube-bench, kubectl and trivy and parses all useful output to excel.
    
    options:
      -h, --help            show this help message and exit
      --excel-out EXCEL_OUT, -e EXCEL_OUT
                            Select a different name for your excel file. Default: 'kubenumerate_results_v1_0.xlsx'
      --kubeaudit-out KUBEAUDIT_OUT, -a KUBEAUDIT_OUT
                            Select an input kubeaudit json file to parse instead of running kubeaudit using your kubeconfig file
      --trivy-file TRIVY_FILE, -f TRIVY_FILE
                            Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file
      --output OUTPUT, -o OUTPUT
                            Select a different folder for all the output (default ./kubenumerate_out/)

## To Do

- [ ] Clear all TODOs
- [ ] Containerise
- [ ] Add verbose flag