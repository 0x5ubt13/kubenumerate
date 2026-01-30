#!/usr/bin/python3

import argparse
import json
import os
import pandas as pd
import pickle
import re
import requests
import shutil
import subprocess
import sys
import time
import platform
import yaml
import zipfile
from datetime import datetime
from packaging.version import Version
from pathlib import Path
import glob
from typing import Any, Dict, List, Optional, Tuple

# Import version management
try:
    from version import get_version
except ImportError:
    # Fallback if version.py is not available
    def get_version() -> str:
        return "2.0.0"


class Kubenumerate:
    """A class to automatically launch and parse several Kubernetes security auditing tools, by Subtle.
    PRs: https://github.com/0x5ubt13/kubenumerate
    """

    def __init__(
        self,
        args: argparse.Namespace = argparse.Namespace(),
        automount: bool = False,
        brew_bin: Optional[str] = "",
        brew_path: str = "",
        cis: bool = False,
        cluster_version: Optional[str] = "",
        date: str = datetime.now().strftime("%b%y"),
        depr_api: bool = False,
        dry_run: bool = False,
        excel_file: str = "kubenumerate_results_v1_0.xlsx",
        home_dir: Path = Path.home(),
        hardened: bool = True,
        host_os: str = platform.system(),
        host_arch: str = "",
        inst_jq: bool = False,
        inst_kubeaudit: bool = False,
        inst_kubebench: bool = False,
        inst_kubectl: bool = False,
        inst_kubiscan: bool = False,
        inst_trivy: bool = False,
        inst_wget: bool = False,
        install: bool = False,
        jq_bin: str = "",
        kubeaudit_bin: str = "",
        kubeaudit_file: str = "",
        kube_bench_bin: str = "",
        kube_bench_file: str = "",
        kubeconfig_path: Optional[str] = None,
        kubectl_bin: str = "kubectl",
        kubectl_path: str = "",
        kubectl_output_path: str = "/tmp/kubenumerate_out/kubectl_output/",
        kubenumerate_path: str = str(Path(os.path.realpath(__file__)).parent.resolve()),
        kube_version: str = "v1.34.1",
        kubiscan_path: str = "/tmp/kubiscan/",
        kubiscan_py: str = "",
        limits: bool = True,
        namespace: str = "-A",
        out_path: str = "/tmp/kubenumerate_out/",
        pkl_recovery: str = "",
        pods: Dict[str, Any] = {},
        pods_file: str = "",
        privesc: bool = False,
        privileged: bool = False,
        py_bin: str = sys.executable,
        requisites: List[str] = [],
        sus_rbac: bool = False,
        trivy_bin: str = "",
        trivy_file: str = "",
        verbosity: int = 1,
        version: Optional[str] = None,
        version_diff: int = 0,
        vuln_image: bool = False,
        wget_bin: str = "",
        summary_word: bool = True,
        summary_output: str = "",
    ) -> None:
        """Initialize attributes"""

        if requisites is None:
            requisites = []
        # user = os.environ.get('USER', 'subtle')
        self.args = args
        self.automount = automount
        self.brew_bin = brew_bin
        self.brew_path = brew_path
        self.cis_detected = cis
        self.cluster_version = cluster_version
        self.date = date
        self.depr_api = depr_api
        self.dry_run = dry_run
        self.excel_file = excel_file
        self.hardened = hardened
        self.home_dir = home_dir
        self.host_os = host_os
        self.host_arch = host_arch
        self.inst_jq = inst_jq
        self.inst_kubeaudit = inst_kubeaudit
        self.inst_kubebench = inst_kubebench
        self.inst_kubectl = inst_kubectl
        self.inst_kubiscan = inst_kubiscan
        self.inst_trivy = inst_trivy
        self.inst_wget = inst_wget
        self.install = install
        self.jq_bin = jq_bin
        self.kubeaudit_bin = kubeaudit_bin
        self.kubeaudit_file = kubeaudit_file
        self.kube_bench_bin = kube_bench_bin
        self.kube_bench_file = kube_bench_file
        self.kubeconfig_path = kubeconfig_path
        self.kubectl_bin = kubectl_bin
        self.kubectl_path = kubectl_path
        self.kubectl_output_path = kubectl_output_path
        self.kubenumerate_path = kubenumerate_path
        self.kube_version = kube_version
        self.kubiscan_path = kubiscan_path
        self.kubiscan_py = kubiscan_py
        self.limits_set = limits
        self.namespace = namespace
        self.out_path = out_path
        self.pods = pods
        self.pods_file = pods_file
        self.privesc_set = privesc
        self.privileged_flag = privileged
        self.sus_rbac = sus_rbac
        self.requisites: List[str] = [] if requisites is None else requisites
        self.trivy_bin = trivy_bin
        self.trivy_file = trivy_file
        self.pkl_recovery = pkl_recovery
        self.py_bin = py_bin
        self.verbosity = verbosity
        # Use dynamic version management if no version is provided
        self.version = version if version is not None else get_version()
        self.version_diff = version_diff
        self.vuln_image = vuln_image
        self.wget_bin = wget_bin
        self.summary_word = summary_word
        self.summary_output = summary_output

    def parse_args(self) -> None:
        """Parse args and return them"""

        # TODO: make no colour flag for those using a light mode terminal. Then in colour methods simply use black
        parser = argparse.ArgumentParser(
            description="Uses local kubeconfig file to launch kubectl, trivy and KubiScan "
            "and parses all useful output to excel."
        )
        parser.add_argument(
            "--cheatsheet",
            "-c",
            action="store_true",
            help="Print commands to extract info from the cluster and work offline",
        )
        parser.add_argument(
            "--dry-run", "-d", action="store_true", help="Don't contact the Kubernetes API - do all work locally"
        )
        parser.add_argument(
            "--excel-out",
            "-e",
            help="Select a different name for your excel file. Default: kubenumerate_results_v1_0.xlsx",
            default="kubenumerate_results_v1_0.xlsx",
        )
        parser.add_argument(
            "--files",
            "-f",
            help="Instruct Kubenumerate to use an already generated "
            "kubectl_output directory with all the necessary files to work offline "
            "(pods.json, deployments.json, etc). Forces --dry-run mode.",
        )
        parser.add_argument("--kubeconfig", "-k", help="Select a specific Kubeconfig file you want to use")
        parser.add_argument(
            "--namespace",
            "-n",
            help="Select a specific namespace to test, if your scope is restricted. Default: -A",
            default="-A",
        )
        parser.add_argument(
            "--output",
            "-o",
            help="Select a different directory for all the output. Default: '/tmp/kubenumerate_out/'",
            default="/tmp/kubenumerate_out/",
        )
        parser.add_argument(
            "--trivy-file",
            "-t",
            help="Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file",
        )
        parser.add_argument(
            "--verbosity",
            "-v",
            help="Select a verbosity level. (0 = quiet | 1 = default | 2 = verbose/debug)",
            default=1,
        )
        parser.add_argument(
            "--skip-summary",
            "-s",
            action="store_true",
            help="Skip generating the summary table in Microsoft Word format (generated by default)",
        )
        parser.add_argument(
            "--summary-output",
            help="Specify the path for the summary Word document. " "Default: {output_dir}/kubenumerate_summary.docx",
        )
        self.args = parser.parse_args()

    def check_os(self) -> None:
        """Detect if script is being run in macOS, Linux or other, and its architecture"""

        class ArchitectureNotSupported(Exception):
            def __init__(self, message: str, supported_architectures: Optional[List[str]] = None) -> None:
                self.message = message
                self.supported_architectures = supported_architectures or ["Linux amd64", "macOS amd64", "macOS arm64"]
                super().__init__(self.message)

            def get_currently_supported_architectures(self) -> str:
                return "".join(f"\n\t- {supported_arch}" for supported_arch in self.supported_architectures)

        try:
            arch = platform.machine().lower()
            match self.host_os:
                case "Darwin":
                    match arch:
                        case "x86_64":
                            self.host_arch = "darwin_amd64"
                        case "arm64" | "aarch64":
                            self.host_arch = "darwin_arm64"
                        case _:
                            raise ArchitectureNotSupported(f"macOS - {arch} not supported.")
                case "Linux":
                    if arch not in ["x86_64", "amd64", "aarch64", "arm64", "x64", "x86_64-v3", "x86_64-v4"]:
                        raise ArchitectureNotSupported(f"Linux {arch} architecture not currently supported.")
                    match arch:
                        case "aarch64" | "arm64":
                            self.host_arch = "linux_arm64"
                        case _:
                            self.host_arch = "linux_amd64"
                case "Windows" | "FreeBSD" | "OpenBSD" | _:
                    raise ArchitectureNotSupported(f"OS {self.host_os} not supported.")
        except ArchitectureNotSupported as e:
            print(
                f'{self.red_text("[-]")} Architecture error: {e}\nCurrently, {self.cyan_text("Kubenumerate")} '
                f"supports the following OS and architectures: {e.get_currently_supported_architectures()}"
            )
            exit(80)
        except Exception as e:
            print(
                f'{self.red_text("[-]")} Error detected when trying to establish the system\'s architecture: {e}\n'
                f'Currently supported OSs and architectures:\n\t- Linux amd64\n\t- macOS amd64\n\t- macOS arm64")'
                f'{self.cyan_text("Kubenumerate")}'
            )
            exit(80)

    def brew_pathfinder(self) -> None:
        """Find brew bin directory"""

        paths = [
            "/home/linuxbrew/.linuxbrew/bin",
            f"{Path.home()}/.linuxbrew/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
        ]

        next_path = next((path for path in paths if os.path.exists(path)), None)
        if next_path:
            self.brew_path = next_path
        self.brew_bin = f"{self.brew_path}/brew" if os.path.exists(f"{self.brew_path}/brew") else None
        return

    def check_requisites(self) -> None:
        """Check for necessary tools. Shout if they're not present in the system"""

        self.check_os()
        self.brew_pathfinder()

        # Kube-bench
        # self.kube_bench_bin = (
        #     "/tmp/kube-bench/kube-bench" if os.path.exists("/tmp/kube-bench/kube-bench") else shutil.which("kube-bench")
        # )
        # if self.kube_bench_bin is None:
        #     self.requisites.append("kube-bench")

        # Kubectl
        kubectl_path = f"{self.brew_path}/kubectl" if self.brew_path else None
        if os.path.exists(str(kubectl_path)):
            self.kubectl_bin = str(kubectl_path)
        elif shutil.which("kubectl"):
            self.kubectl_bin = str(shutil.which("kubectl"))
        else:
            self.kubectl_bin = "kubectl"

        # Trivy
        trivy_pathfinder: Optional[str] = (
            f"{self.brew_path}/trivy" if os.path.exists(f"{self.brew_path}/trivy") else shutil.which("trivy")
        )

        if trivy_pathfinder is not None:
            self.trivy_bin = trivy_pathfinder
        else:
            self.requisites.append("trivy")

        # Kubiscan
        if not shutil.which("kubiscan"):
            if not self.find_kubiscan_bin():
                self.requisites.append("kubiscan")

        # Wget
        wget_bin_pathfinder = (
            f"{self.brew_path}/wget" if os.path.exists(f"{self.brew_path}/wget") else shutil.which("wget")
        )
        if wget_bin_pathfinder is None:
            self.requisites.append("wget")
        else:
            self.wget_bin = wget_bin_pathfinder

        # Jq
        jq_bin_pathfinder = f"{self.brew_path}/jq" if os.path.exists(f"{self.brew_path}/jq") else shutil.which("jq")
        if jq_bin_pathfinder is None:
            self.requisites.append("jq")
        else:
            self.jq_bin = jq_bin_pathfinder

        if len(self.requisites) > 0:
            self.install_requisites()
        else:
            print(f'{self.green_text("[+]")} All necessary software successfully detected in the system.')

    def install_requisites(self) -> None:
        """Check for tools. Offer installing it if they are not present in the system"""
        self.ask_for_permission()

        # # Install kube-bench
        # if self.inst_kubebench:
        #     if not self.install:
        #         print(f'{self.red_text("[-]")} Please install kube-bench: https://github.com/aquasecurity/kube-bench')
        #     else:
        #         if not os.path.exists("/tmp/kube-bench/kube-bench"):
        #             self.install_tool("kube-bench")
        #         else:
        #             self.kube_bench_bin = "/tmp/kube-bench/kube-bench"

        # Install kubectl
        if self.inst_kubectl:
            if not self.install:
                print(f'{self.red_text("[-]")} Please install kubectl: https://kubernetes.io/docs/tasks/tools/#kubectl')
            else:
                self.install_tool("kubectl")

        # Install Trivy
        if self.inst_trivy:
            if not self.install:
                print(f'{self.red_text("[-]")} Please install trivy: https://github.com/aquasecurity/trivy')
            else:
                self.install_tool("trivy")

        # Install wget
        if self.inst_wget:
            if not self.install:
                print(f'{self.red_text("[-]")} Please install wget via apt, brew, or your distro\'s package manager')
            else:
                self.install_tool("wget")

        # Install jq
        if self.inst_jq:
            if not self.install:
                print(f'{self.red_text("[-]")} Please install jq: https://github.com/jqlang/jq')
            else:
                self.install_tool("jq")

        # Install kubiscan
        if self.inst_kubiscan:
            if not self.install:
                print(f'{self.red_text("[-]")} Please install KubiScan: https://github.com/cyberark/KubiScan')
            else:
                if not os.path.isfile("/tmp/kubiscan/KubiScan.py"):
                    self.install_tool("kubiscan")

        if not self.install:
            sys.exit(2)

        print(
            f'{self.green_text("[+]")} Rerunning {self.cyan_text("Kubenumerate")} with all necessary software '
            f"successfully installed in the system. If it fails, please run Kubenumerate again to make sure all "
            f"tools are in your path"
        )
        try:
            os.execv(sys.executable, [f"{self.py_bin}"] + sys.argv)
        except FileNotFoundError:
            print(
                f'{self.red_text("[-]")} Error: Please run {self.cyan_text("Kubenumerate")} again manually '
                f"to make sure all tools are in your path."
            )

    def ask_for_permission(self) -> None:
        """Ask the user for permission to install needed software in the system"""

        # Dictionary to map tools to their attributes
        tool_attribute_mapping = {
            "jq": "inst_jq",
            # "kube-bench": "inst_kubebench",
            "kubectl": "inst_kubectl",
            "trivy": "inst_trivy",
            "kubiscan": "inst_kubiscan",
            "wget": "inst_wget",
        }
        print_brew_message = False

        print(f'{self.cyan_text("[*]")} The following tools are needed:')
        for tool in self.requisites:
            if tool in tool_attribute_mapping:
                setattr(self, tool_attribute_mapping[tool], True)  # Elegant hack
                # if tool != "kube-bench" and tool != "kubiscan" and not print_brew_message:
                if tool != "kubiscan" and not print_brew_message:
                    print_brew_message = True

            print(f'\t- {self.yellow_text(f"{tool}")}')

        if print_brew_message:
            print(
                f'{self.yellow_text("[!]")} {self.cyan_text("Brew")} (https://brew.sh), will be used as the '
                f"package manager to install at least some of these. If it's not in the system, it will also "
                f"be installed.\n"
            )

        while True:
            answer = (
                input(
                    f'{self.yellow_text("[!]")} Do you give your {self.green_text("consent")} to install all of the above?\n'
                    f'\tIf {self.green_text("yes")}, {self.cyan_text("Kubenumerate")} will '
                    f'{self.yellow_text("install all of them")} and {self.yellow_text("restart automatically")}.\n'
                    f'\tIf {self.red_text("no")}, {self.cyan_text("Kubenumerate")} will prompt you where are the official '
                    f"repos to download and install the tools manually from.\n Your choice "
                    f'{self.cyan_text("[y/n]:")} '
                )
                .strip()
                .lower()
            )
            if not answer.startswith("y") and not answer.startswith("n"):
                print(f'{self.red_text("[-]")} Incorrect answer registered. Please type "y" to accept or "n" to deny.')
                continue

            if answer.startswith("y"):
                self.install = True
                break

            if answer.startswith("n"):
                self.install = False
                print(
                    f'{self.red_text("[-]")} No consent given, {self.cyan_text("Kubenumerate")} will exit now. '
                    f"Please find below all the "
                    f"required tools below and their official repositories for you to manually download and install:\n"
                )
                break

        if not shutil.which("brew"):
            # TODO: plug here the pathfinder result, or use it there
            if not os.path.exists("/home/linuxbrew/.linuxbrew/bin/brew"):
                if self.install:
                    self.install_tool("brew")
            else:
                self.brew_bin = "/home/linuxbrew/.linuxbrew/bin/brew"
        else:
            self.brew_bin = shutil.which("brew")

    def install_tool(self, tool: str) -> None:
        """Install the passed tool using brew, or install brew using bash"""

        print(f'\n{self.cyan_text("[*]")} Installing {tool}...')
        shell: str = ""
        try:
            shell = os.environ["SHELL"]
        except KeyError:
            try:
                shell_result = shutil.which("bash")
                if shell_result:
                    shell = shell_result

            except Exception as e:
                print(
                    f'{self.red_text("[-]")} Error: Could not determine the shell. Please set the SHELL environment '
                    f"variable to your shell's path.\nFull error: {e}"
                )
                sys.exit(1)
        c = ""
        try:
            c = f"(echo; echo 'eval \"$({self.brew_bin} shellenv)\"') >> /home/{os.environ['USER']}/"
        except KeyError:
            try:
                c = f"(echo; echo 'eval \"$({self.brew_bin} shellenv)\"') >> {self.home_dir}/"
            except Exception as e:
                print(
                    f'{self.red_text("[-]")} Error: Could not determine the home directory. Please set the HOME '
                    f"environment variable to your home directory's path.\nFull error: {e}"
                )
                sys.exit(1)
        if tool == "brew":
            try:
                subprocess.run(
                    '/bin/bash -c "$(curl -fsSLk https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                    shell=True,
                )
                # Add homebrew to user's PATH
                if "zsh" in shell:
                    subprocess.run(f"{c}.zshrc", shell=True, executable=shell)
                elif "bash" in shell:
                    subprocess.run(f"{c}.bashrc", shell=True, executable=shell)
            except Exception as e:
                print(f'{self.red_text("[-]")} Error whilst installing brew: {e}')
                sys.exit(1)
            return

        # if tool == "kube-bench":
        #     downloaded_tarball = self.fetch_and_download_latest_version_from_github("kube-bench")
        #     kube_bench_path = "/tmp/kube-bench/"
        #     # Untar kube-bench
        #     try:
        #         with tarfile.open(downloaded_tarball, "r:gz") as tarball:
        #             tarball.extractall(path=kube_bench_path)
        #             # Find the kube-bench binary
        #             self.kube_bench_bin = next(
        #                 os.path.join(root, file)
        #                 for root, dirs, files in os.walk(kube_bench_path)
        #                 for file in files
        #                 if file == "kube-bench"
        #             )
        #             # Make it executable
        #             os.chmod(self.kube_bench_bin, 0o755)
        #         if self.verbosity > 1:
        #             print("DEBUG DEV: kube-bench installed successfully")
        #     except Exception as e:
        #         print(f"{self.red_text('[-]')} It was not possible to download kube-bench: {e}")
        #     return
        #     # curl | jq | wget command for debugging purposes:
        #     #   curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | \
        #     #   jq -r '.assets[] | select(.name | test(\"linux_amd64.tar.gz\")) | .browser_download_url' | \
        #     #   wget -i - -P /tmp/kube-bench/"

        if tool == "kubiscan":
            try:
                downloaded_zipball = self.fetch_and_download_latest_version_from_github("kubiscan")
                if self.verbosity > 1:
                    print("DEBUG DEV: kubiscan downloaded successfully")

                kubiscan_path: str = "/tmp/kubiscan/"
                # Extract the tool
                try:
                    with zipfile.ZipFile(downloaded_zipball, "r") as zip_ref:
                        zip_ref.extractall(kubiscan_path)
                    if self.verbosity > 1:
                        print(f"DEV DEBUG: {tool}'s repository downloaded and extracted successfully.")
                except Exception as e:
                    print(f'{self.red_text("[-]")} Error while extracting {tool}: {e}')
                    sys.exit(1)

                # Find the KubiScan.py file in the dynamically named extracted directory
                for root, dirs, files in os.walk(kubiscan_path):
                    if "KubiScan.py" in files:
                        self.kubiscan_py = os.path.join(root, "KubiScan.py")
                if self.verbosity > 1:
                    print("DEBUG DEV: kubiscan path:", self.kubiscan_py)
            except Exception as e:
                print(f"{self.red_text('[-]')} It was not possible to download kubiscan: {e}")
            return

        # Any other tool
        try:
            subprocess.run(f"{self.brew_bin} install {tool}", shell=True, executable=shell)
        except Exception as e:
            print(f'{self.red_text("[-]")} Error whilst installing {tool}: {e}')
            sys.exit(1)

    def find_kubiscan_bin(self) -> bool:
        """Logic needed to cope with dynamically named directory for kubiscan"""
        for root, dirs, files in os.walk(self.kubiscan_path):
            if "KubiScan.py" in files:
                self.kubiscan_py = os.path.join(root, "KubiScan.py")
                self.kubiscan_path = root
                return True
        return False

    def fetch_and_download_latest_version_from_github(self, tool: str) -> str:
        """Fetch latest version of the tool from GitHub, download and extract it. Needs for the repo to be specified"""

        def get_download_url(target: str, latest: Dict[str, Any]) -> Any:
            """Needing to do different download types for different tools as assets are not the same"""
            # if target == "kube-bench":
            #     if self.host_os == "Linux":
            #         return next(
            #             asset["browser_download_url"]
            #             for asset in latest["assets"]
            #             if "linux_amd64.tar.gz" in asset["name"]
            #         )
            #     if self.host_arch == "darwin_amd64":
            #         return next(
            #             asset["browser_download_url"]
            #             for asset in latest["assets"]
            #             if "darwin_amd64.tar.gz" in asset["name"]
            #         )
            #     if self.host_arch == "darwin_arm64":
            #         return next(
            #             asset["browser_download_url"]
            #             for asset in latest["assets"]
            #             if "darwin_arm64.tar.gz" in asset["name"]
            #         )
            if target == "kubiscan":
                # Python package, simply get the zipball
                return latest["zipball_url"]
            return ""

        try:
            tool_tmp_dir, repo, tool_full_path = f"/tmp/{tool}/", "", ""
            try:
                os.makedirs(tool_tmp_dir, exist_ok=True)
            except PermissionError as e:
                print(f'{self.red_text("[-]")} Permission error while creating tmp dir: {e}')
            except Exception as e:
                print(f'{self.red_text("[-]")} Error while creating tmp dir: {e}')

            # if tool == "kube-bench":
            #     repo = "aquasecurity/kube-bench"
            #     tool_full_path = f"{tool_tmp_dir}{tool}.tar.gz"

            if tool == "kubiscan":
                repo = "cyberark/KubiScan"
                tool_full_path = f"{tool_tmp_dir}{tool}.zip"

            # Get the latest release URL first
            response = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
            response.raise_for_status()  # Ensure we notice bad responses
            latest_release_data = response.json()

            download_url = get_download_url(tool, latest_release_data)
            if self.verbosity > 1:
                print("DEBUG DEV: latest_release_data", latest_release_data)
                print("DEBUG DEV: download_url", download_url)

            # Download the file
            subprocess.run(f"{self.wget_bin} -P {tool_tmp_dir} {download_url} -O {tool_full_path}".split(" "))
            return f"{tool_full_path}"
        except Exception as e:
            print(f'{self.red_text("[-]")} Error while fetching {tool}: {e}')
            return ""

    def global_checks(self) -> None:
        """Perform other necessary checks to ensure a correct execution"""

        # Use args if passed
        if hasattr(self.args, "output") and self.args.output:
            self.out_path = f"{os.path.abspath(self.args.output)}/"

        if not hasattr(self.args, "files") or self.args.files is None:
            self.kubectl_output_path = f"{os.path.abspath(self.args.output)}/kubectl_output/"
        else:
            print(
                f'{self.cyan_text("[*]")} --files flag detected. Using existing kubectl output files and '
                f"forcing --dry-run mode."
            )
            self.kubectl_output_path = os.path.abspath(self.args.files)
            self.dry_run = True
            if not os.path.exists(self.kubectl_output_path):
                os.makedirs(self.kubectl_output_path)
                if self.verbosity > 0:
                    print(
                        f'{self.green_text("[+]")} Directory "{self.cyan_text(self.kubectl_output_path)}" created successfully.'
                    )

        if hasattr(self.args, "namespace") and self.args.namespace != "-A":
            self.namespace = f"-n {self.args.namespace}"

        if hasattr(self.args, "dry_run") and self.args.dry_run:
            self.dry_run = True

        # Set correct verbosity
        if self.args.verbosity != 1:
            self.verbosity = int(self.args.verbosity)

        # Use pods file passed for trivy
        if self.args.trivy_file is not None:
            if os.path.exists(self.args.trivy_file):
                self.trivy_file = f"{self.args.trivy_file}"
            else:
                if os.path.exists(f"{os.getcwd()}/{self.args.trivy_file}"):
                    self.trivy_file = f"{os.getcwd()}/{self.args.trivy_file}"
                else:
                    print(f'{self.red_text("[-]")} Trivy file not found')
            if os.path.exists(self.trivy_file):
                if self.verbosity > 0:
                    print(
                        f'{self.green_text("[+]")} Using passed argument "{self.cyan_text(self.trivy_file)}" file as '
                        f"input file for Trivy to avoid sending unnecessary requests to the cluster."
                    )
                with open(self.trivy_file, "r") as f:
                    self.pods = json.loads(f.read())
        else:
            self.pods_file = str(os.path.join(self.kubectl_output_path, "pods.json"))

        # Check path exists and create it if not
        try:
            os.makedirs(self.out_path)
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Directory "{self.cyan_text(self.out_path)}" created successfully.')
        except OSError:
            if self.verbosity > 0:
                print(
                    f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.out_path)}" directory for all output.'
                )

        # Do the same for the kubectl output directory
        if not self.dry_run:
            try:
                os.makedirs(self.kubectl_output_path)
                if self.verbosity > 0:
                    print(
                        f'{self.green_text("[+]")} Directory "{self.cyan_text(self.kubectl_output_path)}" '
                        f"created successfully."
                    )
            except OSError:
                if self.verbosity > 0:
                    print(
                        f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.kubectl_output_path)}" directory for all kubectl output.'
                    )

        if self.dry_run:
            if self.verbosity > 0:
                print(f'{self.cyan_text("[*]")} --dry-run flag detected. Not fetching kubeconfig file.')
                if self.kubectl_output_path is not None and os.path.exists(self.kubectl_output_path):
                    print(
                        f'{self.cyan_text("[*]")} Using existing "{self.cyan_text(self.kubectl_output_path)}" directory for all kubectl output.'
                    )
                if self.pods_file != "" and self.trivy_file is not None and os.path.exists(self.trivy_file):
                    print(
                        f'{self.cyan_text("[*]")} Using passed argument "{self.cyan_text(self.pods_file)}" file as input '
                        f"file for all checks."
                    )
                    self.pods_file = self.trivy_file
        else:
            # Check which kubeconfig file will be used and print current context
            if self.args.kubeconfig is not None:
                self.kubeconfig_path = self.args.kubeconfig

            # OS-agnostic way of checking the home dir for .kube/config
            if self.kubeconfig_path is None or self.kubeconfig_path == "":
                common_kubeconfig_location = f"{Path.home()}/.kube/config"
                if os.path.isfile(common_kubeconfig_location):
                    self.kubeconfig_path = common_kubeconfig_location

            try:
                with open(str(self.kubeconfig_path), "r") as kubeconfig_file:
                    kubeconfig = yaml.safe_load(kubeconfig_file)

                current_context = kubeconfig.get("current-context")
                print(
                    f'{self.green_text("[+]")} {self.yellow_text("Kubeconfig")} file successfully loaded from '
                    f'"{self.yellow_text(f"{self.kubeconfig_path}")}".'
                )
                print(
                    f'{self.green_text("[+]")} Current context to be scanned: '
                    f'"{self.yellow_text(f"{current_context}")}".'
                )

            except Exception as e:
                print(f'{self.red_text("[-]")} Error loading kubeconfig file: {e}')

        # Ensure python3 binary is valid
        if self.py_bin is None:
            self.py_bin = shutil.which("python3") if sys.executable is None else sys.executable
            if shutil.which(self.py_bin) is None:
                self.py_bin = shutil.which("python")

        # Construct excel filename
        self.parse_excel_filename()

    def parse_excel_filename(self) -> None:
        """Construct the Excel filename according to the switches passed to the script"""

        # Default
        if self.args.excel_out is None:
            self.excel_file = f"{self.out_path}kubenumerate_results_v1_0.xlsx"
            return

        # If set, use parsed filename
        self.excel_file = f"{self.out_path}{self.args.excel_out}"

    # def launch_kube_bench(self):
    #     """Check whether a previous kube-bench json file already exists. If not, launch kube-bench"""

    #     # Double-check if a file already exists
    #     self.kube_bench_file = f"{self.out_path}kube_bench_output.json"
    #     if os.path.exists(self.kube_bench_file):
    #         if self.verbosity > 0:
    #             print(
    #                 f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.kube_bench_file)}" kube-bench '
    #                 f"file as input file to avoid sending unnecessary requests to the client's cluster."
    #             )
    #             print(
    #                 f'{self.yellow_text("[!]")} If you want a fresh {self.cyan_text("kube-bench")} output file, run '
    #                 f"the following command and then run this program again:\n\t"
    #                 f'{self.yellow_text(f"rm {self.kube_bench_file}")}'
    #             )
    #         return

    #     # Run kube-bench
    #     self.get_kubebench_output()

    def launch_kubectl(self) -> None:
        """Get everything from kubectl"""

        # Gather all other possible kubectl output in case access to the cluster is lost
        self.kubectl_get_all_yaml_and_json()

        if self.verbosity > 0:
            print(f'{self.green_text("[+]")} Done. All kubectl output saved to {self.cyan_text(self.out_path)}')

    def parse_all_pods(self) -> None:
        """Check whether a previous kubectl json file already exists. If not, launch kubectl"""

        # Abort if user passed file as arg
        if self.args.trivy_file is not None:
            return

        # Exit if file not found
        if not os.path.exists(self.pods_file):
            print(f'{self.red_text("[-]")} Error: No pods file detected. Are you sure kubectl has run fine?')
            return

        if os.path.exists(self.pods_file):
            if self.verbosity > 0:
                print(
                    f'{self.green_text("[+]")} Using "{self.cyan_text(self.pods_file)}" file as input file for '
                    f'{self.cyan_text("Trivy")}, please wait...'
                )
            with open(self.pods_file, "r") as f:
                self.pods = json.loads(f.read())

    def kubectl_get_all_yaml_and_json(self) -> None:
        """Gather all output from kubectl in both json and yaml"""

        # Check if kubeconfig was passed and adjust commands to include the flag
        if self.args.kubeconfig is not None:
            self.kubectl_bin = f"{self.kubectl_bin} --kubeconfig={self.args.kubeconfig}"

        # Get cluster version first
        kubectl_cluster_version_command = f"{self.kubectl_bin} version"
        try:
            cluster_version_process = subprocess.Popen(
                kubectl_cluster_version_command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            cluster_version_stdout, cluster_version_stderr = cluster_version_process.communicate()

            self.cluster_version = str(self.extract_version(cluster_version_stdout))
            with open(f"{self.kubectl_output_path}cluster_version.txt", "w") as f:
                f.write(self.cluster_version)

        except Exception as e:
            self.cluster_version = None
            print(f'{self.red_text("[-]")} Error detected while launching `kubectl version`: {e}')

        # Get all yaml and json about valid resources
        kubectl_json_file = f"{self.kubectl_output_path}all_output.json"
        kubectl_yaml_file = f"{self.kubectl_output_path}all_output.yaml"

        if not os.path.exists(kubectl_json_file):
            Path.touch(Path(kubectl_json_file), 0o644)
            Path.touch(Path(kubectl_yaml_file), 0o644)

        if self.verbosity > 0:
            print(
                f'{self.cyan_text("[*]")} Gathering output from every resource {self.cyan_text(f"kubectl")} has '
                f"permission to get. Please wait..."
            )

        awk_command = "awk '// {print $1}'"
        command = f"{self.kubectl_bin} api-resources --no-headers | {awk_command} | sort -u"
        resources = subprocess.check_output(command, shell=True).decode().split("\n")[:-1]
        total_resources = len(resources)

        if total_resources == 0:
            print(
                f'{self.red_text("[-]")} It was not possible to get number of resources from kubectl. Are you '
                f"connected to the cluster?"
            )
            exit(50)

        # Start progress bar
        start = time.time()
        self.show_status_bar(0, "resources", total_resources, start=start)
        skipped = 0
        try:
            for i, resource in enumerate(resources):
                self.show_status_bar(i + 1, "resources", total_resources, start=start)
                # Skip if it already exists
                if os.path.exists(f"{self.kubectl_output_path}{resource}.json"):
                    if self.verbosity > 0:
                        print(
                            f'{self.yellow_text("[!]")} "{self.kubectl_output_path}{resource}.json" already exists in the '
                            f"system. Skipping..."
                        )
                    continue
                try:
                    Path.touch(Path(f"{self.kubectl_output_path}{resource}.json"), 0o644)
                    Path.touch(Path(f"{self.kubectl_output_path}{resource}.yaml"), 0o644)

                    command = f"{self.kubectl_bin} get {resource} {self.namespace} -o json"
                    process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                except Exception as e:
                    # If forbidden, don't try to do it with yaml
                    print(
                        f'{self.red_text("[-]")} Error detected while launching `kubectl get '
                        f"{resource} {self.namespace} -o json`: {e}"
                    )
                    continue

                # Save the output to its own file
                contents = json.loads(stdout.decode("utf-8"))
                if not contents["items"]:
                    if self.verbosity > 1:
                        print(
                            f'{self.cyan_text("[*]")} DEBUG (DEV branch): not saving '
                            f"file {resource} because it came up empty"
                        )
                    skipped += 1
                    continue

                Path.touch(Path(f"{self.kubectl_output_path}{resource}.json"), 0o644)
                with open(f"{self.kubectl_output_path}{resource}.json", "w") as f:
                    # Check to avoid creating empty list file
                    contents_str = json.dumps(contents, indent=4)
                    f.write(contents_str)

                # ... And if still alive, append to the catch-all file for global queries
                with open(kubectl_json_file, "+a") as f:
                    f.write(contents_str)

                # ... And repeat with yaml
                command = f"kubectl get {resource} {self.namespace} -o yaml"
                process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                # Save the output to its own yaml file
                Path.touch(Path(f"{self.kubectl_output_path}{resource}.yaml"), 0o644)
                with open(f"{self.kubectl_output_path}{resource}.yaml", "w") as f:
                    f.write(stdout.decode("utf-8"))

                # And append to the catch-all file for global queries
                with open(kubectl_yaml_file, "+a") as f:
                    f.write(stdout.decode("utf-8"))

        except ZeroDivisionError:
            print(f'{self.red_text("[-]")} Error: No resources were found. Are you connected to the cluster?\n')

        print("\n", flush=True, file=sys.stdout)
        print(
            f'{self.green_text("[+]")} Successfully extracted '
            f"{self.green_text(str(total_resources - skipped))}/{self.yellow_text(str(total_resources))} resources (the other "
            f"{self.yellow_text(str(skipped))} came up empty so were not collected)."
        )

    def launch_gatherer_tools(self) -> None:
        """Launch trivy (kubeaudit and kube-bench removed)"""

        # Kill switch for the flag --dry-run
        if self.dry_run:
            print(f'{self.cyan_text("[*]")} --dry-run flag detected. Skipping launching kubectl.')

            # Creating empty kube-bench file for the script to work
            # self.kube_bench_file = "/tmp/kube-bench_dummy_file.json"
            # dummy_data = {}

            # with open(self.kube_bench_file, "w") as dummy_f:
            #     json.dump(dummy_data, dummy_f)
            return

        self.launch_kubectl()
        # self.launch_kube_bench()

    def clean_up(self) -> None:
        """Clean up empty files, if generated"""

        if self.dry_run:
            if os.path.exists(self.kube_bench_file):
                os.remove(self.kube_bench_file)
                if self.args.verbosity > 1:
                    print(f"File '{self.kube_bench_file}' deleted successfully.")

    def run(self) -> None:
        """Class main method. Launch trivy and parse it (kubeaudit and kube-bench removed)"""

        # Abort immediately if python 3.11 is not being used
        self.py_bin = "python3" if self.py_bin is None else self.py_bin  # Triple check python is valid
        python_version = (
            subprocess.run(f"{self.py_bin} --version".split(" "), check=True, capture_output=True, text=True)
            .stdout.split(" ")[1]
            .strip()
            .split(".")
        )
        if float(f"{python_version[0]}.{python_version[1]}") < 3.11:
            print(
                f'{self.red_text("[-]")} {self.cyan_text("Python")} version < 3.11 detected. This is a version known '
                f'to cause issues. Please update {self.cyan_text("Python")} and try again.'
            )
            sys.exit(1)

        # Parse args
        self.parse_args()

        # Print banner
        if self.verbosity > 0:
            self.print_banner()

        if self.args.cheatsheet:
            print(f'{self.cyan_text("[*]")} ----- Cheatsheet flag detected -----')
            print(
                f"\nIf your testing host doesn't allow having installed other software than kubeaudit, you can extract "
                f"all you need for {self.cyan_text('Kubenumerate')} to work with the following one-liner:"
            )
            print(
                # TODO: update cheatsheet to include all kubectl calls
                f'{self.cyan_text("kubectl")} get po {self.green_text("-A -o")} json {self.cyan_text(">")}'
                f'{self.yellow_text("pods.json")}; {self.cyan_text("echo")} "Done"\n\n'
                f'Then from your host:\n{self.cyan_text("scp")} {self.green_text("-i")} '
                f'{self.yellow_text("<rsa_id> <remote_user>")}@{self.yellow_text("<10.10.10.10>")}:'
                f'{self.yellow_text("<directory>")}*.json .\n'
            )
            print(
                f'And finally use kubenumerate with the data you just extracted:\n{self.cyan_text("kubenumerate")} '
                f'{self.green_text("--dry-run --trivy-file")} {self.yellow_text("pods.json")}'
            )
            sys.exit(0)

        # Make sure all necessary software is installed
        if self.verbosity > 0:
            print(f'{self.cyan_text("[*]")} ----- Running initial checks -----')
        self.check_requisites()

        # Run all other necessary checks
        self.global_checks()

        # Run tools
        if self.verbosity > 0:
            print(f'\n{self.cyan_text("[*]")} ----- Running kubectl -----')
        self.launch_gatherer_tools()

        # Write to Excel file all findings
        if self.verbosity > 0:
            print(f'\n{self.cyan_text("[*]")} ----- Parsing output, please wait... -----')
        # Check versions difference
        self.kubernetes_version_check()  # TODO: make sure it works with the dry-run flag.
        # Generate local kubeaudit-equivalent findings from kubectl output
        kubeaudit_df = self.generate_kubeaudit_equivalent_df_from_kubectl()
        # with open(self.kube_bench_file, "r") as kube_bench_f:
        with pd.ExcelWriter(self.excel_file, engine="xlsxwriter", mode="w") as writer:
            # Run all Kubeaudit-equivalent methods
            self.apparmor(kubeaudit_df, writer)
            self.asat(kubeaudit_df, writer)
            self.caps(kubeaudit_df, writer)
            self.dep_api(kubeaudit_df, writer)
            self.host_ns(kubeaudit_df, writer)
            self.limits(kubeaudit_df, writer)
            self.mounts(kubeaudit_df, writer)
            self.net_pols(kubeaudit_df, writer)
            self.non_root(kubeaudit_df, writer)
            self.privesc(kubeaudit_df, writer)
            self.privileged(kubeaudit_df, writer)
            self.root_fs(kubeaudit_df, writer)
            self.seccomp(kubeaudit_df, writer)
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} {self.cyan_text("Kubeaudit-equivalent checks")} successfully parsed.')
            # Run Kube-bench methods
            # if not self.dry_run:
            # kube_bench_dict = json.load(kube_bench_f)
            # kube_bench_df = pd.json_normalize(kube_bench_dict, record_path=["Controls", "tests", "results"])
            # self.cis(kube_bench_df, writer)
            # if self.verbosity > 0:
            #     print(f'{self.green_text("[+]")} {self.cyan_text("Kube-bench")} successfully parsed.')
            # Parse all pods for Trivy
            self.parse_all_pods()
            # Run Trivy methods
            vuln_containers = self.trivy_parser(writer)
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} {self.cyan_text("Trivy")} successfully parsed.')
        if self.verbosity >= 0:
            print(f'{self.green_text("[+]")} Done! All output successfully saved to {self.cyan_text(self.excel_file)}.')

        # Generate summary table by default (unless --skip-summary flag is used)
        if not self.args.skip_summary:
            from summary_table import generate_summary_table

            summary_path = (
                self.args.summary_output if self.args.summary_output else f"{self.out_path}kubenumerate_summary.docx"
            )
            try:
                generate_summary_table(kubeaudit_df, vuln_containers, summary_path, self.verbosity)
                if self.verbosity >= 0:
                    print(f'{self.green_text("[+]")} Summary table saved to {self.cyan_text(summary_path)}')
            except Exception as e:
                print(f'{self.red_text("[-]")} Error generating summary table: {e}')

        # TODO: consider feasibility of including icekube

        # Run ExtensiveRoleCheck.py
        if self.verbosity > 0:
            print(f'\n{self.cyan_text("[*]")} ----- Running RBAC checks, please wait... -----')
        self.check_roles()
        # Finish by raising issues to the terminal
        self.raise_issues()

    def check_roles(self) -> None:
        if self.dry_run:
            print(
                f'{self.cyan_text("[*]")} --dry-run flag detected. Using {self.kubectl_output_path} directory to fetch json files'
                f" needed to run ExtensiveRoleCheck.py."
            )
            self.run_extensive_role_check()
            return
        self.run_kubiscan()

    def run_extensive_role_check(self) -> None:
        """Run ExtensiveRoleCheck if not connected to the cluster"""

        role_check_out_path = f"{self.out_path}ExtensiveRoleCheck_output.txt"
        try:
            command = [
                self.py_bin,
                "-m",
                "ExtensiveRoleCheck",
                "--clusterRole",
                f"{self.kubectl_output_path}clusterroles.json",
                "--role",
                f"{self.kubectl_output_path}roles.json",
                "--rolebindings",
                f"{self.kubectl_output_path}rolebindings.json",
                "--clusterrolebindings",
                f"{self.kubectl_output_path}clusterrolebindings.json",
                "--pods",
                f"{self.kubectl_output_path}pods.json",
                "--outputjson",
                role_check_out_path,
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if len(stderr) > 0:
                print(
                    f'{self.red_text("[-]")} Error while running {self.cyan_text("ExtensiveRoleCheck.py")}: '
                    f'{stderr.decode("utf-8")}'
                )
                print(
                    f'{self.cyan_text("[*]")} Ensure all files that the script reads are sane. '
                    f"Perhaps your role does not have enough permissions to get Roles, RoleBindings, ClusterRoles, "
                    f"ClusterRoleBindings, or Pods.\n"
                    f"If otherwise the script is screaming at permissions, it ran fine. Your output should be ready."
                )

            # Save the output to its own file
            Path.touch(Path(role_check_out_path), 0o644)
            with open(f"{role_check_out_path}", "w") as f:
                f.write(stderr.decode("utf-8"))
                f.write(stdout.decode("utf-8"))
                print(
                    f'{self.green_text("[+]")} Done! {self.cyan_text("ExtensiveRoleCheck.py")} output successfully '
                    f"saved to {role_check_out_path}"
                )
        except Exception as e:
            print(f'{self.red_text("[-]")} Error detected while launching `python3 ExtensiveRoleCheck.py`: {e}')

    def run_kubiscan(self) -> None:
        """Run KubiScan if connected to the cluster"""
        if self.args.kubeconfig is not None:
            self.kubiscan_py = f"{self.kubiscan_py} -co {self.args.kubeconfig}"

        try:
            command = f"{self.py_bin} {self.kubiscan_py} -a".split(" ")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if "CRITICAL" in stdout:
                self.sus_rbac = True
            with open(f"{self.out_path}kubiscan.out", "w") as output_kubiscan_file:
                output_kubiscan_file.write(stdout)
            if self.verbosity > 0:
                print(
                    f'{self.green_text("[+]")} Done. {self.cyan_text("KubiScan")} output saved to '
                    f'{self.yellow_text(self.out_path + "kubiscan.out")}'
                )
        except Exception as e:
            print(f'{self.red_text("[-]")} Error while running {self.cyan_text("Kubiscan")}: {e}')

    def kubernetes_version_check(self) -> None:
        """Check whether the cluster's version is outdated"""
        print(
            f"{self.cyan_text('[*]')} Determining latest version of {self.cyan_text('K8s')} from "
            f"{self.cyan_text('GitHub')}'s API..."
        )
        if not self.cluster_version:
            print(
                f'{self.red_text("[-]")} Skipping version check as {self.cyan_text("kubectl")} could not fetch '
                f"cluster's version"
            )
            return

        current_latest = self.fetch_latest_kubernetes_version()
        if current_latest is None:
            print(
                f'{self.red_text("[-]")} This will now default to a hard-coded version ({self.kube_version}). '
                f'Although the developer tries to maintain {self.cyan_text("Kubenumerate")} updated, you should '
                f"ensure this version is up-to-date, otherwise you might flag a false positive."
            )
        else:
            print(
                f'{self.green_text("[+]")} Successfully queried latest version of {self.cyan_text("K8s")}: '
                f'{self.yellow_text(f"{self.kube_version}")}. Comparing against cluster\'s version '
                f'{self.yellow_text("v" + self.cluster_version)}.'
            )
            self.kube_version = current_latest

        if Version(self.cluster_version) < Version(self.kube_version):
            self.version_diff = int(self.kube_version.split(".")[1]) - int(self.cluster_version.split(".")[1])

    def fetch_latest_kubernetes_version(self) -> str:
        """Get latest kubernetes version by querying GitHub's API"""
        # Command for dev purposes:
        # curl -s https://api.github.com/repos/kubernetes/kubernetes/releases/latest | jq -r .tag_name | sed 's/v//'
        try:
            response = requests.get("https://api.github.com/repos/kubernetes/kubernetes/releases/latest")
            data = response.json()
            tag_name_try = data["tag_name"].lstrip("v")
            if isinstance(tag_name_try, str):
                tag_name = tag_name_try
        except Exception as e:
            print(f'{self.red_text("[-]")} Error while running curl trying to fetch kubernetes last version: {e}')
            return "error"

        return tag_name

    @staticmethod
    def extract_version(version_output: bytes) -> Optional[str]:
        """Get cluster's version with RegEx even in case it's a weird string"""

        server_version = ""
        for line in version_output.decode("UTF-8").splitlines():
            if "Server Version" in line:
                server_version = line

        pattern = r"v?(\d+\.\d+\.\d+)"
        match = re.search(pattern, server_version)
        if match:
            return match.group(1)

        print(f"Error: version not found in string {version_output.decode()}")
        return None

    # Colour the terminal!
    @staticmethod
    def red_text(text: str) -> str:
        return f"\033[91m{text}\033[0m"

    @staticmethod
    def cyan_text(text: str) -> str:
        return f"\033[96m{text}\033[0m"

    @staticmethod
    def green_text(text: str) -> str:
        return f"\033[92m{text}\033[0m"

    @staticmethod
    def yellow_text(text: str) -> str:
        return f"\033[93m{text}\033[0m"

    # def get_kubebench_output(self):
    #     """Run 'kube-bench run --targets=node,policies' command and return pointer to output file location"""
    #     if self.verbosity > 0:
    #         print(f'{self.cyan_text("[*]")} Running kube-bench, please wait...')

    #     # TODO: I don't entirely like this logic. It should be:
    #     #   if I know where the kube-bench release directory with the config and the binary is, use that.
    #     #   if not known, and not in /tmp (and thus not installed by kubenumeraga):
    #     #       try to find it
    #     #       if not found:
    #     #           user input -> please tell me where to look for the kube-bench binary
    #     #   ... or use a different tool that isn't kube-bench because not realistically will this be called in a node
    #     kube_bench_config_flag = ""
    #     if self.kube_bench_bin == "/tmp/kube-bench/kube-bench":
    #         kube_bench_config_flag = "--config-dir /tmp/kube-bench/cfg/"

    #     command = f"{self.kube_bench_bin} {kube_bench_config_flag} run --targets=node,policies --json".split(" ")
    #     sudo = False
    #     while True:
    #         try:
    #             if sudo:
    #                 command.insert(0, "sudo")
    #             process = subprocess.run(command, check=True, capture_output=True, text=True)

    #             with open(self.kube_bench_file, "w") as output_kube_bench_file:
    #                 output_kube_bench_file.write(process.stdout)

    #             if self.verbosity > 0:
    #                 print(
    #                     f'{self.green_text("[+]")} Done. Kube-bench output saved to '
    #                     f"{self.cyan_text(self.kube_bench_file)}"
    #                 )
    #                 return

    #         except subprocess.CalledProcessError:
    #             if not sudo:
    #                 print(f'{self.red_text("[-]")} Process exited prematurely. Retrying with sudo...')
    #                 sudo = True
    #                 continue
    #             print(f'{self.red_text("[-]")} Error running kube-bench.')

    # def cis(self, df, writer):
    #     """Parse the kube-bench JSON file to generate a sheet containing the CIS benchmarks that failed and warned"""
    #     try:
    #         # Fail
    #         df_failed_cis = df[df["status"] == "FAIL"]
    #         df_failed_cis = df_failed_cis[
    #             ["status", "test_number", "test_desc", "audit", "AuditConfig", "reason", "remediation"]
    #         ]
    #         df_failed_cis = df_failed_cis.rename(
    #             columns={
    #                 "status": "Status",
    #                 "test_number": "Test Number",
    #                 "test_desc": "Test Description",
    #                 "audit": "Audit",
    #                 "AuditConfig": "Audit Config",
    #                 "reason": "Reason",
    #                 "remediation": "Remediation",
    #             }
    #         )
    #         self.colour_cells_and_save_to_excel(
    #             "CIS Benchmarks - Fail", "Failed CIS Benchmarks", "CIS Benchmarks - Fail", df_failed_cis, writer
    #         )
    #         self.cis_detected = True
    #     except KeyError:
    #         if self.verbosity > 1:
    #             print(f'[{self.cyan_text("*")}] "CIS benchmarks - Fail" not detected')

    #     try:
    #         # Warn
    #         df_warn_cis = df[df["status"] == "WARN"]
    #         df_warn_cis = df_warn_cis[
    #             ["status", "test_number", "test_desc", "audit", "AuditConfig", "reason", "remediation"]
    #         ]
    #         df_warn_cis = df_warn_cis.rename(
    #             columns={
    #                 "status": "Status",
    #                 "test_number": "Test Number",
    #                 "test_desc": "Test Description",
    #                 "audit": "Audit",
    #                 "AuditConfig": "Audit Config",
    #                 "reason": "Reason",
    #                 "remediation": "Remediation",
    #             }
    #         )
    #         self.colour_cells_and_save_to_excel(
    #             "CIS Benchmarks - Warn", "Warn CIS Benchmarks", "CIS Benchmarks - Warn", df_warn_cis, writer
    #         )
    #         self.cis_detected = True
    #     except KeyError:
    #         if self.verbosity > 1:
    #             print(f'[{self.cyan_text("*")}] "CIS benchmarks - Warn" not detected')

    #     try:
    #         # Pass
    #         df_pass_cis = df[df["status"] == "PASS"]
    #         df_pass_cis = df_pass_cis[
    #             ["status", "test_number", "test_desc", "audit", "AuditConfig", "reason", "remediation"]
    #         ]
    #         df_pass_cis = df_pass_cis.rename(
    #             columns={
    #                 "status": "Status",
    #                 "test_number": "Test Number",
    #                 "test_desc": "Test Description",
    #                 "audit": "Audit",
    #                 "AuditConfig": "Audit Config",
    #                 "reason": "Reason",
    #                 "remediation": "Remediation",
    #             }
    #         )
    #         self.colour_cells_and_save_to_excel(
    #             "CIS benchmarks - Pass", "Passed CIS Benchmarks", "CIS benchmarks - Pass", df_pass_cis, writer
    #         )
    #         self.cis_detected = True

    #     except KeyError:
    #         if self.verbosity > 1:
    #             print(f'[{self.cyan_text("*")}] "CIS benchmarks - Warn" not detected')

    def apparmor(self, df: pd.DataFrame, writer: Any) -> None:
        """AppArmor annotation disabled and missing"""
        try:
            # Apparmor disabled
            df_apparmor_disabled = df[df["AuditResultName"] == "AppArmorNotSet"]
            df_apparmor_disabled = df_apparmor_disabled[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "AnnotationValue", "msg"]
            ]
            df_apparmor_disabled = df_apparmor_disabled.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "AnnotationValue": "Annotation Value",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "AppArmor - Not Set",
                "AppArmor is a Mandatory Access Control (MAC) system used by Linux."
                " AppArmor profiles can be specified at the pod level or container level."
                " The container AppArmor profile takes precedence over the pod profile.",
                "Apparmor - Disabled",
                df_apparmor_disabled,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Apparmor - Disabled" not detected')

        # Deprecated in version 1.30 - TODO: perhaps worth checking if cluster version < 1.30????
        # try:
        #     # Apparmor annotation missing
        #     df_apparmor_missing = df[df["AuditResultName"] == "AppArmorAnnotationMissing"]
        #     df_apparmor_missing = df_apparmor_missing[
        #         ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "MissingAnnotation", "msg"]
        #     ]
        #     df_apparmor_missing = df_apparmor_missing.rename(
        #         columns={
        #             "ResourceNamespace": "Resource Namespace",
        #             "ResourceKind": "Resource Kind",
        #             "ResourceName": "Resource Name",
        #             "Container": "Affected Container",
        #             "MissingAnnotation": "Missing Annotation",
        #             "msg": "Recommendation",
        #         }
        #     )
        #     self.colour_cells_and_save_to_excel(
        #         "AppArmor - Missing Annotation",
        #         "AppArmor is a Mandatory Access Control (MAC) system used by Linux. "
        #         "It is enabled by adding container.apparmor.security.beta.kubernetes.io/[container name] as a pod-level"
        #         " annotation and setting its value to either runtime/default or a profile (localhost/[profile name]).",
        #         "Apparmor - Missing",
        #         df_apparmor_missing,
        #         writer,
        #     )
        #     self.hardened = False
        # except KeyError:
        #     if self.verbosity > 1:
        #         print(f'[{self.cyan_text("*")}] "Apparmor - Missing" not detected')

    def asat(self, df: pd.DataFrame, writer: Any) -> None:
        """Automount ServiceAccount Token True And Default SA"""
        try:
            df_automount_sa = df[df["AuditResultName"] == "AutomountServiceAccountTokenTrueAndDefaultSA"]
            df_automount_sa = df_automount_sa[["ResourceNamespace", "ResourceKind", "ResourceName", "msg"]]
            df_automount_sa = df_automount_sa.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Automount ServiceAccount Token True And Default ServiceAccount",
                "Automounting a default service account, or a namespace service account with automounting not disabled "
                "would allow any compromised pod to run API commands against the cluster with the same level of "
                "privileges than the service account. Either automounting should be disabled in the namespace, service "
                "account, or pod declarations, or a non-default service account with sane permissions should be used.",
                "Automount SA",
                df_automount_sa,
                writer,
            )
            self.automount = True
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Automount SA" not detected')

    def caps(self, df: pd.DataFrame, writer: Any) -> None:
        """Capabilities"""
        try:
            # Missing Caps or Security Context
            df_missing_capabilities_or_seccontext = df[df["AuditResultName"] == "CapabilityOrSecurityContextMissing"]
            df_missing_capabilities_or_seccontext = df_missing_capabilities_or_seccontext[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_missing_capabilities_or_seccontext = df_missing_capabilities_or_seccontext.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Capabilities or Security Context Missing",
                "Capabilities (specifically, Linux capabilities), are used for permission management in Linux. "
                "Some capabilities are enabled by default.",
                "Capabilities - Missing",
                df_missing_capabilities_or_seccontext,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Capabilities - Missing" not detected')

        try:
            # Added Caps
            df_added_capabilities = df[df["AuditResultName"] == "CapabilityAdded"]
            df_added_capabilities = df_added_capabilities[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "Metadata", "msg"]
            ]
            df_added_capabilities = df_added_capabilities.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "Metadata": "Metadata",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Capabilities Added that may not be necessary",
                "Capabilities (specifically, Linux capabilities), are used for permission management in Linux. "
                "Some capabilities are enabled by default.",
                "Capabilities - Added",
                df_added_capabilities,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Capabilities - Added" not detected')

        try:
            # Capability Should Drop All
            df_caps_should_drop = df[df["AuditResultName"] == "CapabilityShouldDropAll"]
            df_caps_should_drop = df_caps_should_drop[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_caps_should_drop = df_caps_should_drop.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Capabilities should drop all",
                "Capabilities (specifically, Linux capabilities), are used for permission management in Linux. "
                "Ideally, all capabilities should be dropped."
                "Some capabilities are enabled by default. If capabilities are required, only those required "
                "capabilities should be added",
                "Capabilities - No Drop All",
                df_caps_should_drop,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Capabilities - No Drop All" not detected')

    def dep_api(self, df: pd.DataFrame, writer: Any) -> None:
        """Deprecated API used"""
        try:
            df_dep_api_used = df[df["AuditResultName"] == "DeprecatedAPIUsed"]
            df_dep_api_used = df_dep_api_used[
                [
                    "ResourceName",
                    "ResourceKind",
                    "IntroducedMajor",
                    "IntroducedMinor",
                    "DeprecatedMajor",
                    "DeprecatedMinor",
                    "RemovedMajor",
                    "RemovedMinor",
                    "ResourceApiVersion",
                    "msg",
                ]
            ]
            df_dep_api_used = df_dep_api_used.rename(
                columns={
                    "ResourceName": "Resource Name",
                    "ResourceKind": "Resource Kind",
                    "IntroducedMajor": "Introduced Major",
                    "IntroducedMinor": "Introduced Minor",
                    "DeprecatedMajor": "Deprecated Major",
                    "DeprecatedMinor": "Deprecated Minor",
                    "RemovedMajor": "Removed Major",
                    "RemovedMinor": "Removed Minor",
                    "ResourceApiVersion": "Resource API Version",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Deprecated APIs in use",
                "Deprecated APIs in use were found. They will be removed, see recommended replacement APIs.",
                "Deprecated API Used",
                df_dep_api_used,
                writer,
            )
            self.depr_api = True
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Deprecated API Used')

    def host_ns(self, df: pd.DataFrame, writer: Any) -> None:
        """Host namespace"""
        try:
            # Namespace Host PID True
            df_ns_host_pid_true = df[df["AuditResultName"] == "NamespaceHostPIDTrue"]
            df_ns_host_pid_true = df_ns_host_pid_true[["ResourceNamespace", "ResourceKind", "ResourceName", "msg"]]
            df_ns_host_pid_true = df_ns_host_pid_true.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Host Namespace - hostPID set to true",
                "HostPID - Controls whether the pod containers can share the host process ID namespace. "
                "Note that when paired with ptrace this can be used to escalate privileges outside of the container "
                "(ptrace is forbidden by default).",
                "Host Namespace - hostPID true",
                df_ns_host_pid_true,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Host Namespace - hostPID true" not detected')

        try:
            # Namespace Host PID True
            df_ns_host_network_true = df[df["AuditResultName"] == "NamespaceHostNetworkTrue"]
            df_ns_host_network_true = df_ns_host_network_true[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "msg"]
            ]
            df_ns_host_network_true = df_ns_host_network_true.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Host Namespace - hostNetwork set to true",
                "HostNetwork - Controls whether the pod may use the node network namespace. "
                "Doing so gives the pod access to the loopback device, services listening on localhost, and could "
                "be used to snoop on network activity of other pods on the same node.",
                "Host Namespace-hostNetwork true",
                df_ns_host_network_true,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Host Namespace - hostNetwork true" not detected')

    def limits(self, df: pd.DataFrame, writer: Any) -> None:
        """Limits"""
        try:
            # Limits Not Set
            df_limits_not_set = df[df["AuditResultName"] == "LimitsNotSet"]
            df_limits_not_set = df_limits_not_set[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_limits_not_set = df_limits_not_set.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Resource Limits Not Set",
                "Containers without resource limits set could be used to consume resources which would have a "
                "negative impact on the cluster",
                "Limits - Not set",
                df_limits_not_set,
                writer,
            )
            self.limits_set = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Limits - Not set" not detected')

        try:
            # Limits CPU Not Set
            df_limits_cpu_not_set = df[df["AuditResultName"] == "LimitsCPUNotSet"]
            df_limits_cpu_not_set = df_limits_cpu_not_set[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_limits_cpu_not_set = df_limits_cpu_not_set.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "CPU Limits Not Set",
                "Containers without CPU limits set could be used to consume resources which would have a "
                "negative impact on the cluster",
                "Limits - CPU Not set",
                df_limits_cpu_not_set,
                writer,
            )
            self.limits_set = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Limits - CPU Not set" not detected')

    def mounts(self, df: pd.DataFrame, writer: Any) -> None:
        """Mounted paths"""
        try:
            # Sensitive Paths Mounted
            df_sensitive_paths_mounted = df[df["AuditResultName"] == "SensitivePathsMounted"]
            df_sensitive_paths_mounted = df_sensitive_paths_mounted[
                [
                    "MountName",
                    "MountPath",
                    "MountReadOnly",
                    "MountVolume",
                    "MountVolumeHostPath",
                    "ResourceNamespace",
                    "ResourceKind",
                    "ResourceName",
                    "Container",
                    "msg",
                ]
            ]
            df_sensitive_paths_mounted = df_sensitive_paths_mounted.rename(
                columns={
                    "MountName": "Mount Name",
                    "MountPath": "Mount Path",
                    "MountReadOnly": "Mount ReadOnly",
                    "MountVolume": "Mount Volume",
                    "MountVolumeHostPath": "Mount Volume Host Path",
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Sensitive Paths Mounted to Containers",
                "Mounting some sensitive host paths (like /etc, /proc, or /var/run/docker.sock) may allow a "
                "container to access sensitive information from the host like credentials or to spy on other workloads'"
                " activity. These sensitive paths should not be mounted.",
                "Mounts - Sensitive Paths",
                df_sensitive_paths_mounted,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Mounts - Sensitive Paths" not detected')

    def net_pols(self, df: pd.DataFrame, writer: Any) -> None:
        """Network policies"""
        try:
            # Missing Default Deny Ingress And Egress Network Policy
            df_default_deny_missing = df[df["AuditResultName"] == "MissingDefaultDenyIngressAndEgressNetworkPolicy"]
            df_default_deny_missing = df_default_deny_missing[["ResourceKind", "ResourceName", "msg"]]
            df_default_deny_missing = df_default_deny_missing.rename(
                columns={
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "NetworkPolicies - No default deny Ingress/Egress",
                "Just like with firewall rules, the best practice is to deny all internet traffic by default "
                "and explicitly allow expected traffic (that is, allow expected traffic rather than deny unexpected "
                "traffic).",
                "NetworkPolicies - No deny",
                df_default_deny_missing,
                writer,
            )
            self.hardened = False
            self.sus_rbac = True
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "NetworkPolicies - No deny" not detected')

        try:
            # AllowAllEgressNetworkPolicyExists
            df_allow_all = df[df["AuditResultName"] == "AllowAllEgressNetworkPolicyExists"]
            df_allow_all = df_allow_all[["ResourceKind", "ResourceName", "msg"]]
            df_allow_all = df_allow_all.rename(
                columns={
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Allow All Egress NetworkPolicy Exists",
                "Just like with firewall rules, the best practice is to deny all internet traffic by default "
                "and explicitly allow expected traffic (that is, allow expected traffic rather than deny unexpected "
                "traffic).",
                "NetworkPolicies - Allow all",
                df_allow_all,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "NetworkPolicies - Allow all" not detected')

    def non_root(self, df: pd.DataFrame, writer: Any) -> None:
        """Running as"""
        try:
            # Run As Non Root PSC Nil CSC Nil
            df_run_as_non_root_nil = df[df["AuditResultName"] == "RunAsNonRootPSCNilCSCNil"]
            df_run_as_non_root_nil = df_run_as_non_root_nil[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_run_as_non_root_nil = df_run_as_non_root_nil.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Run As Non Root - Pod SecurityContext/Container SecurityContext Nil",
                "Containers should be run as a non-root user with the minimum required permissions (principle "
                "of least privilege). This can be done by setting runAsNonRoot to true in either the PodSecurityContext"
                " or container SecurityContext. If runAsNonRoot is unset in the Container SecurityContext, it will "
                "inherit the value of the Pod SecurityContext. If runAsNonRoot is unset in the Pod SecurityContext, "
                "it defaults to false which means it must be explicitly set to true in either the Container "
                "SecurityContext or the Pod SecurityContext for the nonroot audit to pass.",
                "Non Root - Missing",
                df_run_as_non_root_nil,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Non Root - Missing" not detected')

        try:
            # Run As User CSC Root
            df_run_as_user_csc_root = df[df["AuditResultName"] == "RunAsUserCSCRoot"]
            df_run_as_user_csc_root = df_run_as_user_csc_root[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_run_as_user_csc_root = df_run_as_user_csc_root.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Run As Non Root - CSC UID 0",
                "Containers should be run as a non-root user with the minimum required permissions (principle "
                "of least privilege). This can be done by setting runAsNonRoot to true in either the PodSecurityContext"
                " or container SecurityContext. If runAsNonRoot is unset in the Container SecurityContext, it will "
                "inherit the value of the Pod SecurityContext. If runAsNonRoot is unset in the Pod SecurityContext, "
                "it defaults to false which means it must be explicitly set to true in either the Container "
                "SecurityContext or the Pod SecurityContext for the nonroot audit to pass.",
                "Non Root - CSC UID 0",
                df_run_as_user_csc_root,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Non Root - CSC UID 0" not detected')

        try:
            # Run As User PSC Root
            df_run_as_user_psc_root = df[df["AuditResultName"] == "RunAsUserPSCRoot"]
            df_run_as_user_psc_root = df_run_as_user_psc_root[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_run_as_user_psc_root = df_run_as_user_psc_root.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Run As User UID 0 - Pod SecurityContext ",
                "Containers should be run as a non-root user with the minimum required permissions (principle "
                "of least privilege). This can be done by setting runAsNonRoot to true in either the PodSecurityContext"
                " or container SecurityContext. If runAsNonRoot is unset in the Container SecurityContext, it will "
                "inherit the value of the Pod SecurityContext. If runAsNonRoot is unset in the Pod SecurityContext, "
                "it defaults to false which means it must be explicitly set to true in either the Container "
                "SecurityContext or the Pod SecurityContext for the nonroot audit to pass.",
                "Non Root - PSC UID 0",
                df_run_as_user_psc_root,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Non Root - PSC UID 0" not detected')

    def privesc(self, df: pd.DataFrame, writer: Any) -> None:
        """Privilege escalation"""
        try:
            # Allow Privilege Escalation Nil
            df_allow_privilege_escalation_nil = df[df["AuditResultName"] == "AllowPrivilegeEscalationNil"]
            df_allow_privilege_escalation_nil = df_allow_privilege_escalation_nil[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_allow_privilege_escalation_nil = df_allow_privilege_escalation_nil.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Privilege Escalation - No Explicit Deny",
                "allowPrivilegeEscalation controls whether a process can gain more privileges than its parent "
                "process. Privilege escalation should always be explicitly denied by setting allowPrivilegeEscalation "
                "to false in the container's SecurityContext.",
                "PrivilegeEscalation - Nil",
                df_allow_privilege_escalation_nil,
                writer,
            )
            self.privesc_set = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "PrivilegeEscalation - Nil" not detected')

        try:
            # Allow Privilege Escalation True
            df_allow_privilege_escalation_true = df[df["AuditResultName"] == "AllowPrivilegeEscalationTrue"]
            df_allow_privilege_escalation_true = df_allow_privilege_escalation_true[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_allow_privilege_escalation_true = df_allow_privilege_escalation_true.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Privilege Escalation - flag 'privilegeEscalation' set to True",
                "allowPrivilegeEscalation controls whether a process can gain more privileges than its parent "
                "process. Privilege escalation should always be explicitly denied by setting allowPrivilegeEscalation "
                "to false in the container's SecurityContext.",
                "PrivilegeEscalation - True",
                df_allow_privilege_escalation_true,
                writer,
            )
            self.privesc_set = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "PrivilegeEscalation - True" not detected')

    def privileged(self, df: pd.DataFrame, writer: Any) -> None:
        """Privileged"""
        try:
            # Privileged Nil
            df_privileged_nil = df[df["AuditResultName"] == "PrivilegedNil"]
            df_privileged_nil = df_privileged_nil[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_privileged_nil = df_privileged_nil.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Privileged flag not set to false in SecurityContext",
                "Running a container as privileged gives all capabilities to the container, and it also lifts "
                "all the limitations enforced by the device cgroup controller. In other words, the container can then "
                "do almost everything that the host can do. This option exists to allow special use-cases, like running"
                " Docker within Docker, but should not be used in most cases.",
                "Privileged - Nil",
                df_privileged_nil,
                writer,
            )
            self.sus_rbac = True
            self.privileged_flag = True
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Privileged - Nil" not detected')

        try:
            # Privileged True
            df_privileged_true = df[df["AuditResultName"] == "PrivilegedTrue"]
            df_privileged_true = df_privileged_true[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_privileged_true = df_privileged_true.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Privileged flag set to true in SecurityContext",
                "Running a container as privileged gives all capabilities to the container, and it also lifts "
                "all the limitations enforced by the device cgroup controller. In other words, the container can then "
                "do almost everything that the host can do. This option exists to allow special use-cases, like running"
                " Docker within Docker, but should not be used in most cases.",
                "Privileged - True",
                df_privileged_true,
                writer,
            )
            self.sus_rbac = True
            self.privileged_flag = True
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Privileged - True" not detected')

    def root_fs(self, df: pd.DataFrame, writer: Any) -> None:
        """Root filesystem"""
        try:
            # ReadOnlyRootFilesystem Nil
            df_read_only_root_filesystem_nil = df[df["AuditResultName"] == "ReadOnlyRootFilesystemNil"]
            df_read_only_root_filesystem_nil = df_read_only_root_filesystem_nil[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_read_only_root_filesystem_nil = df_read_only_root_filesystem_nil.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "readOnlyRootFilesystem not set",
                "If a container does not need to write files, it should be run with a read-only filesystem.",
                "Root FileSystem - ReadOnly Nil",
                df_read_only_root_filesystem_nil,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Root FileSystem - ReadOnly Nil" not detected')

    def seccomp(self, df: pd.DataFrame, writer: Any) -> None:
        """Seccomp profile"""
        try:
            # Seccomp Profile Missing
            df_seccomp_profile_missing = df[df["AuditResultName"] == "SeccompProfileMissing"]
            df_seccomp_profile_missing = df_seccomp_profile_missing[
                ["ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]
            ]
            df_seccomp_profile_missing = df_seccomp_profile_missing.rename(
                columns={
                    "ResourceNamespace": "Resource Namespace",
                    "ResourceKind": "Resource Kind",
                    "ResourceName": "Resource Name",
                    "Container": "Affected Container",
                    "msg": "Recommendation",
                }
            )
            self.colour_cells_and_save_to_excel(
                "Seccomp Profile Missing",
                "Seccomp is enabled by adding a seccomp profile to the security context. The seccomp profile can "
                "be either added to a pod security context, which enables seccomp for all containers within that pod, "
                "or a security context, which enables seccomp only for that container.",
                "Seccomp - Missing",
                df_seccomp_profile_missing,
                writer,
            )
            self.hardened = False
        except KeyError:
            if self.verbosity > 1:
                print(f'[{self.cyan_text("*")}] "Seccomp - Missing" not detected')

    @staticmethod
    def show_status_bar(iteration: int, resource: str, count: int, start: float, size: int = 50) -> None:
        """Quick function to show a nice status bar to stdout"""
        x = int(size * iteration / count)
        if iteration != 0:
            remaining = ((time.time() - start) / iteration) * (count - iteration)
            mins, sec = divmod(remaining, 60)
            time_str = f"{mins:.0f}m {sec:02.0f}s"
        else:
            time_str = "N/A"

        print(
            f"\t Scanned: [{u'█' * x}{' ' * (size - x)}] {iteration}/{count} {resource}. ETA: {time_str}",
            end="\r",
            file=sys.stderr,
            flush=True,
        )

    def recover_from_aborted_scan(self) -> Tuple[List[Any], List[Any], List[Any], int, bool]:
        """Detect if there are any aborted lists"""

        if os.path.isfile(self.pkl_recovery) and os.path.getsize(self.pkl_recovery) > 0:
            # File exists and has content. Restore it
            with open(self.pkl_recovery, "rb") as recovery_file:
                data = pickle.load(recovery_file)
                scanned_images: List[Any] = list(data[0])
                vuln_images: List[Any] = list(data[1])
                vuln_containers: List[Any] = list(data[2])
                iteration: int = data[3]
                print(
                    f'{self.cyan_text("[*]")} Restoring data from previous interrupted scan: '
                    f"jumping to pod #{iteration}"
                )
            return scanned_images, vuln_images, vuln_containers, iteration, True

        # Otherwise, return new lists
        return [], [], [], 0, False

    def recover_from_aborted_scan_dict(self) -> Tuple[Dict[str, Any], int, bool]:
        """Detect if there are any aborted lists"""

        if os.path.isfile(self.pkl_recovery) and os.path.getsize(self.pkl_recovery) > 0:
            # File exists and has content. Restore it
            with open(self.pkl_recovery, "rb") as recovery_file:
                data = pickle.load(recovery_file)
                images, iteration = data
                print(
                    f'{self.cyan_text("[*]")} Restoring data from previous interrupted scan: '
                    f"jumping to pod #{iteration}"
                )
            return images, iteration, True

        # Otherwise, return new vars
        return {}, 0, False

    def run_trivy(self, image_name: str) -> Optional[Dict[str, Any]]:
        """Run Trivy against the specified image and handle errors"""

        command = f"{self.trivy_bin} i -q --scanners vuln --severity HIGH,CRITICAL --format json {image_name}"

        try:
            process = subprocess.run(command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

            # Check if process failed
            if process.returncode != 0:
                if self.verbosity > 1:
                    print(f"Trivy failed on {image_name}: {process.stderr.decode()}")
                return None

            # Check for empty output
            trivy_output = process.stdout.decode("utf-8").strip()
            if not trivy_output:
                if self.verbosity > 1:
                    print(f"Empty trivy output for {image_name}")
                return None

            # Try to parse JSON output
            try:
                result: Dict[str, Any] = json.loads(trivy_output)
                return result
            except json.JSONDecodeError:
                if self.verbosity > 1:
                    print(f"Invalid JSON from trivy for {image_name}")
                return None

        except subprocess.TimeoutExpired:
            if self.verbosity > 1:
                print(f"Trivy timed out on {image_name}")
            return None
        except Exception as e:
            if self.verbosity > 1:
                print(f"Error running trivy on {image_name}: {str(e)}")
            return None

    def trivy_parser(self, writer: Any) -> List[List[Any]]:
        """Run trivy against every image in every container and save output to Excel file.
        The function will recover from any crashed instance
        """

        # Check if no pods were found
        pods = []
        try:
            pods = self.pods.get("items", [])
        except AttributeError:
            print(f'{self.red_text("[-]")} No pods detected, aborting...')
            return []
        except Exception as e:
            print(f'{self.red_text("[-]")} An error occurred: {e}')
            return []

        total_pods = len(pods)
        if total_pods == 0:
            print(
                f'{self.red_text("[-]")} No pods detected, aborting...\n{self.red_text("[-]")} Please check the '
                f"permissions of your current role with the following command:\n\t"
                f'{self.yellow_text("kubectl auth can-i --list")}'
            )
            return []

        # Create recovery file if it doesn't exist
        self.pkl_recovery = f"{self.out_path}.kubenumerate_trivy_log_lists.pkl"
        if not os.path.exists(self.pkl_recovery):
            Path.touch(Path(self.pkl_recovery), 0o644)

        if self.verbosity > 1:
            print(
                f'{self.yellow_text("[!]")} Launching trivy to scan every unique container image for vulns. This '
                f'might take a while, please wait...\n{self.yellow_text("[!]")} Known issues: if stuck at 0, '
                f"run: \n\ttrivy i --download-java-db-only"
            )
            print(f'{self.cyan_text("[*]")} Scanning {self.yellow_text(f"{total_pods}")} pods detected...')

        # Recover from aborted scan, if needed
        scanned_images, vuln_images, vuln_containers, iteration, recovered_file = self.recover_from_aborted_scan()

        # Start progress bar
        start = time.time()
        self.show_status_bar(iteration, "pods", total_pods, start)

        # Main loop to go through all images
        for i, pod in enumerate(pods):
            self.show_status_bar(i + 1, "pods", total_pods, start)
            # Check to see if this is a repeating test
            if iteration == total_pods - 1:
                if self.verbosity > 0:
                    print(
                        f'{self.red_text("[-]")} It looks like this test was already run in the past.\nIf you want to '
                        f"redo the assessment, select a different output directory, or run\n\t"
                        f'{self.yellow_text(f"rm {self.pkl_recovery}")}'
                    )
                break

            # Skip to the recovered point
            if recovered_file and i < iteration:
                continue

            # Save progress with every new loop in case of needing to recover
            # from fatal error
            data = (scanned_images, vuln_images, vuln_containers, i)
            with open(self.pkl_recovery, "r+b") as recovery_file:
                pickle.dump(data, recovery_file)

            # Check if the image has already been scanned
            try:
                namespace = pod["metadata"]["namespace"]
                pod_name = pod["metadata"]["name"]
                for container in pod.get("spec", {}).get("containers", []):
                    image_name = container.get("image")
                    container_name = container.get("name")
                    if image_name:
                        # Don't scan the same image twice
                        already_checked, already_found_vulns = False, False
                        if image_name in scanned_images:
                            already_checked = True
                            if image_name in vuln_images:
                                already_found_vulns = True

                        # Not vuln but image already checked, skip it
                        if already_checked and not already_found_vulns:
                            if self.verbosity > 1:
                                print(f"Debug: {image_name} already checked. Skipping")
                            continue

                        # Vuln image found duplicated, add pod info to vuln list and skip it
                        if already_found_vulns:
                            if self.verbosity > 1:
                                print(f"Debug: {image_name} already_found_vulns")
                            try:
                                previous_image = [img for img in vuln_containers if img[1] == image_name]
                                new_image = [
                                    namespace,
                                    image_name,
                                    pod_name,
                                    container_name,
                                    previous_image[0][4],  # crits
                                    previous_image[0][5],  # crit CVEs
                                    previous_image[0][6],  # highs
                                    previous_image[0][7],  # high CVEs
                                ]
                                vuln_containers.append(new_image)
                                continue
                            except UnboundLocalError as e:
                                # Getting UnboundLocalError when recovering from previous scan.
                                if self.verbosity > 1:
                                    print(f"Debug: UnboundLocalError when recovering from previous scan: {str(e)}")
                                continue

                        # Proceed scanning the image
                        scanned_images.append(image_name)
                        try:
                            if self.verbosity > 1:
                                print(f"Scanning image {image_name}")
                            vulnerabilities = self.run_trivy(image_name)
                            if vulnerabilities is None:
                                if self.verbosity > 1:
                                    print(f"Skipping {image_name} due to trivy scan failure")
                                continue

                            # Get number of CVEs
                            highs, found_high_CVEs, crits, found_crit_CVEs = 0, [], 0, []
                            for result in vulnerabilities.get("Results", []):
                                for vulnerability in result.get("Vulnerabilities", []):
                                    vuln_id = vulnerability.get("VulnerabilityID")
                                    if "HIGH" in vulnerability.get("Severity"):
                                        if vuln_id not in found_high_CVEs:
                                            found_high_CVEs.append(vulnerability.get("VulnerabilityID"))
                                            highs += 1
                                    if "CRITICAL" in vulnerability.get("Severity"):
                                        if vuln_id not in found_crit_CVEs:
                                            found_crit_CVEs.append(vulnerability.get("VulnerabilityID"))
                                            crits += 1

                            if highs > 0 or crits > 0:
                                if self.verbosity > 1:
                                    print("Vuln image detected:", image_name)
                                vuln_images.append(image_name)
                                new_image = [
                                    namespace,
                                    image_name,
                                    pod_name,
                                    container_name,
                                    crits,
                                    found_crit_CVEs,
                                    highs,
                                    found_high_CVEs,
                                ]
                                vuln_containers.append(new_image)
                        except subprocess.CalledProcessError as e:
                            if self.verbosity > 1:
                                print(f"Error scanning with Trivy: {str(e)}")
                        except KeyError as e:
                            if self.verbosity > 1:
                                print("Key error:", str(e))
            except KeyboardInterrupt:
                print("\n", flush=True, file=sys.stdout)
                if self.verbosity > 0:
                    print(
                        f'\n{self.cyan_text("[*]")} ^C detected. Recovery file saved to '
                        f"{self.cyan_text(self.pkl_recovery)}..."
                    )
                sys.exit(99)
            # except json.decoder.JSONDecodeError or ValueError as e:
            #     if self.verbosity > 1:
            #         print(f"Error: {str(e)}")
            except KeyError as e:
                if self.verbosity > 1:
                    print("Key error:", e)

        # Flush the terminal stream
        print("\n", flush=True, file=sys.stdout)

        if len(vuln_containers) != 0:
            self.vuln_image = True
            df = pd.DataFrame(vuln_containers)
            df.columns = [
                "Namespace",
                "Image Name",
                "Pod Name",
                "Affected Container",
                "CRITS",
                # TODO: edit this tab to present the CVEs in a better way? Currently it's VERY ugly
                "CRIT CVEs affecting image",
                "HIGHS",
                "HIGH CVEs affecting image",
            ]
            self.colour_cells_and_save_to_excel(
                "Images with Vulnerable Tags being used",
                "Scanners picked up containers being affected by High and Critical well-known vulnerabilities. "
                "These images' tags should be upgraded as soon as possible",
                "Vulnerable Images",
                df,
                writer,
            )
        else:
            print(f'{self.green_text("[+]")} No images found containing any high- or critical-risk issues')

        return vuln_containers

    def raise_issues(self) -> None:
        """Suggest what issues might be present"""

        issues_raised = {
            "version": False,
            "hardened": False,
            "automount": False,
            "vuln_image": False,
            "privileged": False,
            "cis_detected": False,
            "limits_set": False,
        }

        if (
            self.hardened
            and not self.automount
            and not self.vuln_image
            and self.version_diff <= 1
            and not self.privileged_flag
            and not self.cis_detected
            and not self.limits_set
        ):
            print(f'{self.green_text("[+]")} No findings detected in the cluster.')
            return

        print(f'{self.cyan_text("[*]")} Suggested findings detected:')

        # Kubernetes Version Outdated
        if self.version_diff > 1:
            print(f'\t{self.red_text("[!]")} Kubernetes Version Outdated')
            issues_raised["version"] = True

        # Containers Not Hardened
        if not self.hardened:
            print(f'\t{self.red_text("[!]")} Containers Not Hardened')
            issues_raised["hardened"] = True

        # TODO: implement a check that ignores some false positives when cloud provider manages kube-system
        # Containers Automount Service Account Token
        if self.automount:
            print(f'\t{self.red_text("[!]")} Containers Automount Service Account Token')
            issues_raised["automount"] = True

        # Vulnerable Container Images Pulled From Third-Party Repositories
        if self.vuln_image:
            print(f'\t{self.red_text("[!]")} Vulnerable Container Images Pulled From Third-Party Repositories')
            issues_raised["vuln_image"] = True

        # Containers Allowing Privilege Escalation
        if self.privileged_flag:
            print(f'\t{self.red_text("[!]")} Containers Allowing Privilege Escalation')
            issues_raised["privileged"] = True

        # # CIS Benchmarks
        # if self.cis_detected:
        #     print(f'\t{self.red_text("[!]")} CIS Benchmarks')
        #     issues_raised["cis_detected"] = True

        # CPU usage
        if not self.limits_set:
            print(f'\t{self.red_text("[!]")} CPU usage')
            issues_raised["limits_set"] = True

        # Suggest checking RBAC's output
        if self.sus_rbac:
            if self.dry_run:
                print(f'\t{self.yellow_text("[!]")} Check ExtensiveRoleCheck\'s output')
            else:
                print(f'\t{self.yellow_text("[!]")} Check KubiScan\'s output provided at {self.out_path}kubiscan.out')

        with open("test_issues_dict.txt", "w") as f:
            f.write(str(issues_raised))

    # TODO: Minimal improvement: check whether @static works fine here
    @staticmethod
    def colour_cells_and_save_to_excel(
        title: str, subtitle: str, sheet_name: str, df: pd.DataFrame, writer: Any
    ) -> None:
        workbook = writer.book
        worksheet = workbook.add_worksheet(sheet_name)
        worksheet.set_zoom(90)

        worksheet.set_column(0, len(df.columns) - 1, 20)
        header_format = workbook.add_format(
            {"font_name": "Calibri", "bg_color": "#A93545", "bold": True, "font_color": "white", "align": "left"}
        )
        title_format = workbook.add_format(
            {"font_name": "Calibri", "bg_color": "#A93545", "font_color": "white", "font_size": 20}
        )
        bg_format1 = workbook.add_format({"bg_color": "#E2E2E2"})
        bg_format2 = workbook.add_format({"bg_color": "white"})

        worksheet.merge_range("A1:AC1", title, title_format)
        worksheet.merge_range("A2:AC2", subtitle)
        worksheet.set_row(2, 15)  # row height 15

        for col_num, value in enumerate(df.columns.values):
            worksheet.write(2, col_num, value, header_format)
        worksheet.freeze_panes(3, 0)
        skip_three = 3
        for row in range(df.shape[0] + 3):
            if skip_three > 0:
                skip_three -= 1
                continue
            worksheet.set_row(row, cell_format=(bg_format1 if row % 2 == 0 else bg_format2))

        df.to_excel(writer, index=False, sheet_name=sheet_name, startrow=3, header=False)

    def print_banner(self) -> None:
        banner = f"""
           {self.cyan_text('  +-----+')}{self.red_text('  1. -----')}
           {self.cyan_text(' /     /|')}{self.red_text('  2. -----')}
           {self.cyan_text('+-----+ |')}{self.yellow_text('  3. -----')}
           {self.cyan_text('|     | +')}{self.yellow_text('  4. -----')}
           {self.cyan_text('|     |/')}{self.green_text('  5. -----')}
           {self.cyan_text('+-----+')}{self.green_text('  6. -----')}"""
        print(
            f"{self.cyan_text(banner)}\n"
            f"\t     Kubenumerate\n"
            f'\t  {self.green_text("By 0x5ubt13")} {self.yellow_text(f"v{self.version}")}\n'
        )

    def get_normalised_deprecated_apis_dict(
        self,
    ) -> Dict[Tuple[str, str], Tuple[int, int, int, int, int | None, int | None]]:
        """Generate a list of tuples containing normalised (apiVersion, kind) for deprecated APIs"""

        raw = {
            # Example: (apiVersion, kind)
            ("v1", "ComponentStatus"): (1, 0, 1, 19, None, None),
            ("apps/v1beta1", "Deployment"): (1, 6, 1, 9, 1, 16),
            ("extensions/v1beta1", "Deployment"): (1, 2, 1, 9, 1, 16),
            ("extensions/v1beta1", "DaemonSet"): (1, 2, 1, 9, 1, 16),
            ("extensions/v1beta1", "ReplicaSet"): (1, 2, 1, 9, 1, 16),
            ("extensions/v1beta1", "Ingress"): (1, 2, 1, 14, 1, 22),
            # Added as of 1.34.1:
            ("policy/v1beta1", "PodDisruptionBudget"): (1, 5, 1, 21, 1, 25),
            ("policy/v1beta1", "PodSecurityPolicy"): (1, 3, 1, 21, 1, 25),
            ("autoscaling/v2beta1", "HorizontalPodAutoscaler"): (1, 6, 1, 19, 1, 25),
            ("autoscaling/v2beta2", "HorizontalPodAutoscaler"): (1, 12, 1, 23, 1, 26),
            ("batch/v1beta1", "CronJob"): (1, 8, 1, 21, 1, 25),
            ("networking.k8s.io/v1beta1", "Ingress"): (1, 14, 1, 19, 1, 22),
            ("networking.k8s.io/v1beta1", "IngressClass"): (1, 18, 1, 19, 1, 22),
            ("discovery.k8s.io/v1beta1", "EndpointSlice"): (1, 16, 1, 21, 1, 25),
            ("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition"): (1, 7, 1, 16, 1, 22),
            ("admissionregistration.k8s.io/v1beta1", "MutatingWebhookConfiguration"): (1, 9, 1, 16, 1, 22),
            ("admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration"): (1, 9, 1, 16, 1, 22),
            ("scheduling.k8s.io/v1beta1", "PriorityClass"): (1, 11, 1, 14, 1, 17),
            ("coordination.k8s.io/v1beta1", "Lease"): (1, 11, 1, 14, 1, 17),
            ("resource.k8s.io/v1beta1", "ResourceClaim"): (1, 33, 1, 33, 1, 34),
            ("resource.k8s.io/v1beta1", "ResourceSlice"): (1, 33, 1, 33, 1, 34),
            # TODO: To revisit in future versions to either update, or:
            # TODO: Implement a dynamic `k get --raw /apis` check so that we don't need to update this manually
        }

        return {self.normalise(api, kind): versions for (api, kind), versions in raw.items()}

    def generate_kubeaudit_equivalent_df_from_kubectl(self) -> pd.DataFrame:
        """
        Parse kubectl output (pods, deployments, etc.) and generate a DataFrame with the columns expected by the
        kubeaudit check methods. This replaces the need for kubeaudit output.
        """

        findings = []
        # Static mappings for deprecated APIs and sensitive mount paths
        deprecated_apis = self.get_normalised_deprecated_apis_dict()
        sensitive_mount_paths = ["/etc", "/proc", "/var/run/docker.sock", "/var/run/cri.sock", "/root", "/var/lib"]
        resource_files = []
        if self.dry_run:
            self.find_pods_file_dry_run()
            # print(f"Debug: self.trivy_file = {self.trivy_file}")
            if self.kubectl_output_path:
                resource_files = glob.glob(f"{self.kubectl_output_path}/*.json")
                print(f'{self.cyan_text("[*]")} Dry run mode: using {self.trivy_file} as input')
            else:
                resource_files.append(self.trivy_file)
                print(f'{self.cyan_text("[*]")} Dry run mode: using {self.trivy_file} as input')
        else:
            resource_files = glob.glob(f"{self.kubectl_output_path}/*.json")
        for resource_file in resource_files:
            # print(f'{self.cyan_text("[*]")} Parsing {resource_file}...')
            if resource_file.endswith("all_output.json") or resource_file.endswith("cluster_version.txt"):
                continue
            try:
                with open(resource_file, "r") as f:
                    data = json.load(f)
                    # print(f"debug: {data}")
                items = data.get("items", [])
                for item in items:
                    kind = item.get("kind", "")
                    # print(f"debug: kind {kind}")
                    api_version = item.get("apiVersion", "")
                    metadata = item.get("metadata", {})
                    spec = item.get("spec", {})
                    namespace = metadata.get("namespace", "default")
                    name = metadata.get("name", "")
                    # Deprecated API check
                    key = self.normalise(api_version, kind)
                    # print("debug: key", key)
                    if key in deprecated_apis:
                        intro_maj, intro_min, depr_maj, depr_min, rem_maj, rem_min = deprecated_apis[key]
                        print(f"debug: deprecated API found: {api_version}, {kind}")
                        findings.append(
                            {
                                "AuditResultName": "DeprecatedAPIUsed",
                                "ResourceNamespace": metadata.get("namespace", "default"),
                                "ResourceKind": kind,
                                "ResourceName": metadata.get("name", ""),
                                "IntroducedMajor": intro_maj,
                                "IntroducedMinor": intro_min,
                                "DeprecatedMajor": depr_maj,
                                "DeprecatedMinor": depr_min,
                                "RemovedMajor": rem_maj,
                                "RemovedMinor": rem_min,
                                "ResourceApiVersion": api_version,
                                "msg": f"{kind} uses deprecated API version {api_version}.",
                            }
                        )

                    # Pod-level and template checks
                    pod_spec = spec.get("template", {}).get("spec", spec)  # For controllers, use template.spec
                    pod_security_ctx = pod_spec.get("securityContext", {})
                    # print(f"debug: pod_spec {pod_spec}")
                    containers = pod_spec.get("containers", [])
                    # AppArmor, Seccomp, ASAT, Capabilities, Limits, Mounts, Non-root, Privesc, Privileged, RootFS
                    for container in containers:
                        # print(f"debug: container {container}")
                        cname = container.get("name", "")
                        security_ctx = container.get("securityContext", {})
                        anns = item.get("metadata", {}).get("annotations", {})
                        # AppArmor
                        # ------ legacy method ------
                        # apparmor_ann = None
                        # # print (f"debug: anns {anns}")
                        # # print(f"debug: spec {spec}")
                        # if not anns and "template" in spec:
                        #     anns = spec["template"].get("metadata", {}).get("annotations", {})
                        # apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{cname}"
                        # print(f"debug: apparmor_key {apparmor_key}")
                        # if apparmor_key not in anns:
                        if "appArmorProfile" not in pod_security_ctx and "appArmorProfile" not in security_ctx:
                            findings.append(
                                {
                                    "AuditResultName": "AppArmorNotSet",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "AppArmor profile not set.",
                                }
                            )

                        # Seccomp
                        seccomp_ann = anns.get("seccomp.security.alpha.kubernetes.io/pod")
                        if (
                            not seccomp_ann
                            and not pod_spec.get("securityContext", {}).get("seccompProfile")
                            and not security_ctx.get("seccompProfile")
                        ):
                            findings.append(
                                {
                                    "AuditResultName": "SeccompProfileMissing",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "Seccomp profile missing.",
                                }
                            )
                        # AutomountServiceAccountToken
                        automount = pod_spec.get("automountServiceAccountToken", True)
                        sa_name = pod_spec.get("serviceAccountName", "default")
                        if automount and sa_name == "default":
                            findings.append(
                                {
                                    "AuditResultName": "AutomountServiceAccountTokenTrueAndDefaultSA",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "msg": "Pod automounts service account token and uses default SA.",
                                }
                            )
                        # Capabilities
                        if not security_ctx or not security_ctx.get("capabilities"):
                            findings.append(
                                {
                                    "AuditResultName": "CapabilityOrSecurityContextMissing",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "Missing securityContext or capabilities.",
                                }
                            )
                        else:
                            caps = security_ctx.get("capabilities", {})
                            if "add" in caps and caps["add"]:
                                findings.append(
                                    {
                                        "AuditResultName": "CapabilityAdded",
                                        "ResourceNamespace": namespace,
                                        "ResourceKind": kind,
                                        "ResourceName": name,
                                        "Container": cname,
                                        "Metadata": str(caps["add"]),
                                        "msg": f"Capabilities added: {caps['add']}",
                                    }
                                )
                            if not ("drop" in caps and "ALL" in caps["drop"]):
                                findings.append(
                                    {
                                        "AuditResultName": "CapabilityShouldDropAll",
                                        "ResourceNamespace": namespace,
                                        "ResourceKind": kind,
                                        "ResourceName": name,
                                        "Container": cname,
                                        "msg": "Container should drop all capabilities.",
                                    }
                                )
                        # Limits
                        resources = container.get("resources", {})
                        limits = resources.get("limits", {})
                        if not limits:
                            findings.append(
                                {
                                    "AuditResultName": "LimitsNotSet",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "No resource limits set.",
                                }
                            )
                        if "cpu" not in limits:
                            findings.append(
                                {
                                    "AuditResultName": "LimitsCPUNotSet",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "No CPU limit set.",
                                }
                            )
                        # Mounts
                        for vol_mount in container.get("volumeMounts", []):
                            mount_path = vol_mount.get("mountPath", "")
                            for sensitive in sensitive_mount_paths:
                                if mount_path.startswith(sensitive):
                                    findings.append(
                                        {
                                            "AuditResultName": "SensitivePathsMounted",
                                            "MountName": vol_mount.get("name", ""),
                                            "MountPath": mount_path,
                                            "MountReadOnly": vol_mount.get("readOnly", False),
                                            "MountVolume": vol_mount.get("name", ""),
                                            "MountVolumeHostPath": "",  # Could be filled by matching with volumes
                                            "ResourceNamespace": namespace,
                                            "ResourceKind": kind,
                                            "ResourceName": name,
                                            "Container": cname,
                                            "msg": f"Sensitive path mounted: {mount_path}",
                                        }
                                    )
                        # Non-root
                        run_as_non_root = security_ctx.get("runAsNonRoot")
                        run_as_user = security_ctx.get("runAsUser")
                        pod_run_as_non_root = pod_security_ctx.get("runAsNonRoot")
                        pod_run_as_user = pod_security_ctx.get("runAsUser")
                        if run_as_non_root is None and pod_run_as_non_root is None:
                            findings.append(
                                {
                                    "AuditResultName": "RunAsNonRootPSCNilCSCNil",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "runAsNonRoot not set in Pod or Container SecurityContext.",
                                }
                            )
                        if run_as_user == 0:
                            findings.append(
                                {
                                    "AuditResultName": "RunAsUserCSCRoot",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "Container runs as UID 0.",
                                }
                            )
                        if pod_run_as_user == 0:
                            findings.append(
                                {
                                    "AuditResultName": "RunAsUserPSCRoot",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "Pod runs as UID 0.",
                                }
                            )
                        # Privilege escalation
                        ape = security_ctx.get("allowPrivilegeEscalation")
                        if ape is None:
                            findings.append(
                                {
                                    "AuditResultName": "AllowPrivilegeEscalationNil",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "allowPrivilegeEscalation not set.",
                                }
                            )
                        elif ape is True:
                            findings.append(
                                {
                                    "AuditResultName": "AllowPrivilegeEscalationTrue",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "allowPrivilegeEscalation is true.",
                                }
                            )
                        # Privileged
                        privileged = security_ctx.get("privileged")
                        if privileged is None:
                            findings.append(
                                {
                                    "AuditResultName": "PrivilegedNil",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "privileged not set.",
                                }
                            )
                        elif privileged is True:
                            findings.append(
                                {
                                    "AuditResultName": "PrivilegedTrue",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "privileged is true.",
                                }
                            )
                        # Root filesystem
                        ro_rootfs = security_ctx.get("readOnlyRootFilesystem")
                        if not ro_rootfs:
                            findings.append(
                                {
                                    "AuditResultName": "ReadOnlyRootFilesystemNil",
                                    "ResourceNamespace": namespace,
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "Container": cname,
                                    "msg": "readOnlyRootFilesystem not set or false.",
                                }
                            )
                    # Host namespace
                    if pod_spec.get("hostPID") is True:
                        findings.append(
                            {
                                "AuditResultName": "NamespaceHostPIDTrue",
                                "ResourceNamespace": namespace,
                                "ResourceKind": kind,
                                "ResourceName": name,
                                "msg": "hostPID is true.",
                            }
                        )
                    if pod_spec.get("hostNetwork") is True:
                        findings.append(
                            {
                                "AuditResultName": "NamespaceHostNetworkTrue",
                                "ResourceNamespace": namespace,
                                "ResourceKind": kind,
                                "ResourceName": name,
                                "msg": "hostNetwork is true.",
                            }
                        )
                    # NetworkPolicies (global, not per pod)
                    if kind == "NetworkPolicy":
                        spec_policy = item.get("spec", {})
                        # pod_selector = spec_policy.get("podSelector", {})
                        policy_types = spec_policy.get("policyTypes", [])
                        if "Ingress" in policy_types and not spec_policy.get("ingress"):
                            findings.append(
                                {
                                    "AuditResultName": "MissingDefaultDenyIngressAndEgressNetworkPolicy",
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "msg": "No default deny ingress policy.",
                                }
                            )
                        if "Egress" in policy_types and not spec_policy.get("egress"):
                            findings.append(
                                {
                                    "AuditResultName": "MissingDefaultDenyIngressAndEgressNetworkPolicy",
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "msg": "No default deny egress policy.",
                                }
                            )
                        # Allow all egress
                        if "Egress" in policy_types and spec_policy.get("egress") == [{}]:
                            findings.append(
                                {
                                    "AuditResultName": "AllowAllEgressNetworkPolicyExists",
                                    "ResourceKind": kind,
                                    "ResourceName": name,
                                    "msg": "Allow all egress policy exists.",
                                }
                            )
            except Exception as e:
                if self.verbosity > 1:
                    print(f"Error parsing {resource_file}: {e}")
        # Return as DataFrame with expected columns (even if empty)
        columns = [
            "AuditResultName",
            "ResourceNamespace",
            "ResourceKind",
            "ResourceName",
            "Container",
            "AnnotationValue",
            "MissingAnnotation",
            "Metadata",
            "IntroducedMajor",
            "IntroducedMinor",
            "DeprecatedMajor",
            "DeprecatedMinor",
            "RemovedMajor",
            "RemovedMinor",
            "ResourceApiVersion",
            "MountName",
            "MountPath",
            "MountReadOnly",
            "MountVolume",
            "MountVolumeHostPath",
            "msg",
        ]
        df = pd.DataFrame(findings, columns=columns)
        return df

    def normalise(self, api_version: str, kind: str) -> tuple[str, str]:
        return api_version.strip().lower(), kind.strip()

    def find_pods_file_dry_run(self) -> None:
        """Find the pods.json file in dry-run mode"""
        # print("debug: find_pods_file_dry_run() called")
        possible_files = [
            "pods.json",
            "pod.json",
            "kubectl_get_pods.json",
            "kubectl_get_pods_-A.json",
            "kubectl_get_pods_--all-namespaces.json",
        ]
        found = False
        for filename in possible_files:
            filepath = f"{self.kubectl_output_path}/{filename}"
            if os.path.isfile(filepath):
                self.trivy_file = filepath
                found = True
                print(f'{self.green_text("[+]")} Found pods file for dry run: {self.cyan_text(filepath)}')
                break
        if not found:
            print(
                f'{self.red_text("[-]")} Error: No pods.json file found in {self.cyan_text(self.kubectl_output_path)}.'
            )
            sys.exit(1)


def main() -> None:
    instance = Kubenumerate()
    instance.run()


if __name__ == "__main__":
    main()
