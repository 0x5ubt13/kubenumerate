#!/usr/bin/python3

import argparse
import datetime
import json
import multiprocessing
import os
import pandas as pd
from pathlib import Path
import pickle
import shutil
import subprocess
import sys
import time


class Kubenumerate():
    """ A class to automatically launch and parse several Kubernetes security auditing tools, by Subtle
        PRs: https://github.com/0x5ubt13/kubenumerate
    """

    def __init__(self, args="", automount=False, cis=False, date=datetime.datetime.now().strftime("%b%y"), depr_api=False, excel_file="", hardened=True, kubeaudit_file="", kube_bench_file="", kubectl_pods_file="",
                 kubectl_path=f"{os.getcwd()}/kubenumerate_out/kubectl_output/", limits=True, out_path=f"{os.getcwd()}/kubenumerate_out/", pkl_recovery="", pods="", privesc=False, privileged=False, requisites=True, trivy_file="", verbosity=1, vuln_image=False):
        """Initialize attributes"""

        self.args              = args
        self.automount         = automount
        self.cis_detected      = cis
        self.date              = date
        self.depr_api          = depr_api
        self.excel_file        = excel_file
        self.hardened          = hardened
        self.kubeaudit_file    = kubeaudit_file
        self.kube_bench_file   = kube_bench_file
        self.kubectl_path      = kubectl_path
        self.kubectl_pods_file = kubectl_pods_file
        self.limits_set        = limits
        self.out_path          = out_path
        self.pods              = pods
        self.privesc_set       = privesc
        self.privileged_flag   = privileged
        self.requisites        = requisites
        self.trivy_file        = trivy_file
        self.pkl_recovery      = pkl_recovery
        self.vuln_image        = vuln_image
        self.verbosity         = verbosity # TODO finish implementing it

    def parse_args(self):
        """Parse args and return them"""

        parser = argparse.ArgumentParser(
            description='Uses local kubeconfig file to launch kubeaudit, kube-bench, kubectl and trivy and parses all useful output to excel.')
        parser.add_argument(
            '--excel-out',
            '-e',
            help="Select a different name for your excel file. Default: 'kubenumerate_results_v1_0.xlsx'",
            default='kubenumerate_results_v1_0.xlsx')
        parser.add_argument(
            '--kubeaudit-out',
            '-a',
            help="Select an input kubeaudit json file to parse instead of running kubeaudit using your kubeconfig file")
        parser.add_argument(
            '--trivy-file',
            '-f',
            help="Run trivy from a pods dump in json instead of running kubectl using your kubeconfig file")
        parser.add_argument(
            '--output',
            '-o',
            help="Select a different folder for all the output (default ./kubenumerate_out/)",
            default=f"{os.getcwd()}/kubenumerate_out/")
        parser.add_argument(
            '--verbosity',
            '-v',
            help="Select a verbosity level. (0 = quiet | default = 1 | verbose = 2)",
            default=1)
        # TODO: implement thoroughly verbose/quiet flags

        self.args = parser.parse_args()

    def check_requisites(self):
        """Check for kubeaudit, kube-bench and trivy. Exit if they are not present in the system"""

        if not shutil.which("kubeaudit"):
            print(f'{self.red_text("[-]")} Please install kubeaudit: https://github.com/Shopify/kubeaudit')
            self.requisites = False
        if not shutil.which("kube-bench"):
            print(f'{self.red_text("[-]")} Please install kube-bench: https://github.com/aquasecurity/kube-bench')
            self.requisites = False
        if not shutil.which("kubectl"):
            print(f'{self.red_text("[-]")} Please install kubectl: https://kubernetes.io/docs/tasks/tools/#kubectl')
            self.requisites = False
        if not shutil.which("kubeaudit"):
            print(f'{self.red_text("[-]")} Please install trivy: https://github.com/aquasecurity/trivy')
            self.requisites = False
        if not self.requisites:
            #TODO: offer the user installing them for absolute laziness' sake
            sys.exit(2)
        
        if self.verbosity > 0:
            print(f'{self.green_text("[+]")} All necessary software successfully detected in the system.')

    def global_checks(self):
        """Perform other necessary cheks to ensure a correct execution"""

        # Check out path exists and create it if not
        if self.args.output is not None:
            self.out_path = f'{os.path.abspath(self.args.output)}/'
            self.kubectl_path = f'{os.path.abspath(self.args.output)}/kubectl_output/'
        try:
            os.makedirs(self.out_path)
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Folder "{self.cyan_text(self.out_path)}" created successfully.')
        except OSError:
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.out_path)}" folder for all output.')

        try:
            os.makedirs(self.kubectl_path)
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Folder "{self.cyan_text(self.kubectl_path)}" created successfully.')
        except OSError:
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.kubectl_path)}" folder for all output.')

        # Construct excel filename
        self.parse_excel_filename()

    def parse_excel_filename(self):
        """Construct the excel filename according to the switches passed to the script"""

        if not self.args.excel_out:
            self.excel_file = f"{self.out_path}kubenumerate_results_v1_0.xlsx"
            return
        
        # If set, use parsed filename
        self.excel_file = self.args.excel_out

    def launch_kubeaudit(self, args):
        """Check whether a previous kubeaudit json file already exists. If not, launch kubeaudit"""

        if self.args.kubeaudit_out is not None:
            # TODO: refactor this to instruct kubeaudit to go one by one over the yaml manifests extracted now by kubectl
            # Read filename from flag
            self.kubeaudit_file = self.args.kubeaudit_out
        else:
            # Use default
            self.kubeaudit_file = f"{self.out_path}kubeaudit_all.json"

        # Check if exists
        if os.path.exists(self.kubeaudit_file):
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.kubeaudit_file)}" kubeaudit file as input file to avoid sending unnecesary requests to the client\'s cluster.')
                print(f'{self.yellow_text("[!]")} If you want a fresh kubeaudit output file, run the following command and run this program again:\n\t{self.yellow_text(f"rm {self.kubeaudit_file}")}')
            return

        # Launch it
        self.get_kubeaudit_all()

    def launch_kube_bench(self):
        """Check whether a previous kube-bench json file already exists. If not, launch kube-bench"""

        # Double-check if a file already exists
        self.kube_bench_file = f"{self.out_path}kube_bench_output.json"
        if os.path.exists(self.kube_bench_file):
            if self.verbosity > 0:
                print(f'{self.green_text("[+]")} Using existing "{self.cyan_text(self.kube_bench_file)}" kube-bench file as input file to avoid sending unnecesary requests to the client\'s cluster.')
                print(f'{self.yellow_text("[!]")} If you want a fresh kube-bench output file, run the following command and run this program again:\n\t{self.yellow_text(f"rm {self.kube_bench_file}")}')
            return

        # Run kube-bench
        self.get_kubebench_output()

    def launch_kubectl(self):
        """Get everything from kubectl"""

        # Gather all other possible kubectl output in case access to the
        # cluster is lost
        self.kubectl_get_all_yaml_and_json()

        # Populate self.pods for trivy
        self.kubectl_get_all_pods()

        if self.verbosity > 0:
            print(f'{self.green_text("[+]")} Done. All kubectl output saved to {self.cyan_text(self.out_path)}')

    def kubectl_get_all_pods(self):
        """Check whether a previous kubectl json file already exists. If not, launch kubectl"""

        # First check if args passed a pods json dump
        if self.args.trivy_file is not None:
            self.trivy_file = f"{os.getcwd()}/{self.args.trivy_file}"
            if os.path.exists(self.trivy_file):
                if self.verbosity > 1:
                    print(f'{self.green_text("[+]")} Using passed argument "{self.cyan_text(self.trivy_file)}" file as input file for Trivy to avoid sending unnecesary requests to the cluster.')
                with open(self.trivy_file, "r") as f:
                    self.pods = json.loads(f.read())
                return

        # Use a freshly extracted pods file
        self.kubectl_pods_file = f"{self.kubectl_path}pods.json"
        if os.path.exists(self.kubectl_pods_file):
            if self.verbosity > 1:
                print(f'{self.green_text("[+]")} Using "{self.cyan_text(self.kubectl_pods_file)}" file as input file for Trivy to avoid sending unnecesary requests to the cluster.')
            with open(self.kubectl_pods_file, "r") as f:
                self.pods = json.loads(f.read())

    def kubectl_get_all_yaml_and_json(self):
        """Gather all output from kubectl in both json and yaml"""

        kubectl_json_file = f'{self.kubectl_path}all_output.json'
        kubectl_yaml_file = f'{self.kubectl_path}all_output.yaml'

        if not os.path.exists(kubectl_json_file):
            Path.touch(kubectl_json_file, 0o644)
            Path.touch(kubectl_yaml_file, 0o644)

        if self.verbosity > 0:
            print(f'{self.cyan_text("[*]")} Gathering output from every resource {self.cyan_text(f"kubectl")} has permission to get. Please wait...')
        command = "kubectl api-resources --no-headers | awk '// {print $1}' | sort -u".split(" ")
        resources = subprocess.check_output(command, shell=True).decode().split("\n")[:-1]
        total_resources = len(resources)

        # Start progress bar
        start = time.time()
        try:
            self.show_status_bar(0, total_resources, start=start)
            for i, resource in enumerate(resources):
                # Skip if it already exists
                if os.path.exists(f'{self.kubectl_path}{resource}.json'):
                    continue
                try:
                    command = f"kubectl get {resource} -A -o json".split(" ")
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                except:
                    # If forbidden, don't try to do it with yaml
                    continue

                # Save the output to its own file
                with open(f'{self.kubectl_path}{resource}.json', "w") as f:
                    f.write(stdout.decode("utf-8"))

                # And append to the catch-all file for global queries
                with open(kubectl_json_file, '+a') as f:
                    f.write(stdout.decode("utf-8"))

                # Repeat with yaml
                command = f"kubectl get {resource} -A -o yaml"
                process = subprocess.Popen(
                    command.split(" "),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                # Save the output to its own file
                with open(f'{self.kubectl_path}{resource}.yaml', "w") as f:
                    f.write(stdout.decode("utf-8"))

                # And append to the catch-all file for global queries
                with open(kubectl_yaml_file, '+a') as f:
                    f.write(stdout.decode("utf-8"))
                self.show_status_bar(i + 1, total_resources, start=start)

        except ZeroDivisionError:
            print(f'{self.red_text["-"]} No resources were found. Are you connected to the cluster?')

        print("\n", flush=True, file=sys.stderr)

    def Run(self):
        """Class main method. Launch kubeaudit, kube-bench and trivy and parse them"""

        if self.verbosity > 0:
            print(f'{self.cyan_text("[*]")} ----- Running initial checks -----')
        # Parse args
        self.parse_args()

        # Make sure all necessary software is installed
        self.check_requisites()

        # Run all other necessary cheks
        self.global_checks()

        if self.verbosity > 0:
            print(f'\n{self.cyan_text("[*]")} ----- Running kubectl, kubeaudit and kube-bench -----')

        # Run tools
        self.launch_kubectl()
        self.launch_kubeaudit()
        self.launch_kube_bench()

        if self.verbosity > 0:
            print(f'\n{self.cyan_text("[*]")} ----- Parsing kubeaudit, kube-bench and trivy output, please wait... -----')

        # Write to excel file all findings
        with open(self.kubeaudit_file, "r") as kubeaudit_f:
            with open(self.kube_bench_file, "r") as kube_bench_f:
                with pd.ExcelWriter(self.excel_file, engine='xlsxwriter', mode="w") as writer:
                    # Make dataframe for Kubeaudit
                    kubeaudit_df = pd.read_json(kubeaudit_f, lines=True)

                    # Run all kubeaudit methods
                    self.apparmor(kubeaudit_df, writer)
                    self.asat(kubeaudit_df, writer)
                    self.caps(kubeaudit_df, writer)
                    self.dep_api(kubeaudit_df, writer)
                    self.hostns(kubeaudit_df, writer)
                    self.image(kubeaudit_df, writer)  # TODO
                    self.limits(kubeaudit_df, writer)
                    self.mounts(kubeaudit_df, writer)
                    self.netpols(kubeaudit_df, writer)
                    self.nonroot(kubeaudit_df, writer)
                    self.privesc(kubeaudit_df, writer)
                    self.rootfs(kubeaudit_df, writer)
                    self.seccomp(kubeaudit_df, writer)
                    if self.verbosity > 0:
                        print(f'{self.green_text("[+]")} Kubeaudit successfuly parsed')

                    # Run Kube-bench methods
                    kube_bench_dict = json.load(kube_bench_f)
                    kube_bench_df = pd.json_normalize(
                        kube_bench_dict, record_path=['Controls', 'tests', 'results'])
                    self.cis(kube_bench_df, writer)
                    if self.verbosity > 0:
                        print(f'{self.green_text("[+]")} Kube-bench successfuly parsed')

                    # Run trivy methods
                    self.trivy_parser(writer)
                    # self.trivy_parser_dict(self.trivy_extractor(), writer=writer) # Attempt to make it more efficient; to test
                    if self.verbosity > 0:
                        print(f'{self.green_text("[+]")} Trivy successfuly parsed')

        if self.verbosity >= 0:
            print(f'{self.green_text("[+]")} Done! All output successfully saved to {self.cyan_text(self.excel_file)}')

        self.raise_issues()

    # Colour the terminal!
    @staticmethod
    def red_text(text):
        return f'\033[91m{text}\033[0m'

    @staticmethod
    def cyan_text(text):
        return f'\033[96m{text}\033[0m'

    @staticmethod
    def green_text(text):
        return f'\033[92m{text}\033[0m'

    @staticmethod
    def yellow_text(text):
        return f'\033[93m{text}\033[0m'

    def get_kubeaudit_all(self):
        """Run 'kubeaudit all' command and save output to a file"""

        # TODO: add verbosity flag
        if self.verbosity > 0:
            print(f'{self.cyan_text("[*]")} Running kubeaudit, please wait...')

        # TODO: Add check for stderr
        command = "kubeaudit all -p json"
        process = subprocess.Popen(
            command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stderr is not None:
            # Raise error
            print(f'{self.red_text("[-]")} Error running kubeaudit: {stderr}')

        # Save the output to a file
        with open(self.kubeaudit_file, "w") as output_kubeaudit_file:
            output_kubeaudit_file.write(stdout.decode("utf-8"))

        if self.verbosity > 0:
            print(f'{self.green_text("[+]")} Done. Kubeaudit output saved to {self.cyan_text(self.kubeaudit_file)}')

    def get_kubebench_output(self):
        """Run 'kube-bench run --targets=node,policies' command and return pointer to output file location"""

        # TODO: add verbosity flag
        if self.verbosity > 0:
            print(f'{self.cyan_text("[*]")} Running kube-bench, please wait...')

        # TODO: Add check for stderr
        command = "kube-bench run --targets=node,policies --json".split(" ")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stderr is not None:
            # Raise error
            print(f'{self.red_text("[-]")} Error running kube-bench: {stderr}')

        # Save the output to a file
        with open(self.kube_bench_file, "w") as output_kube_bench_file:
            output_kube_bench_file.write(stdout.decode("utf-8"))

        if self.verbosity > 0:
            print(f'{self.green_text("[+]")} Done. Kube-bench output saved to {self.cyan_text(self.kube_bench_file)}')

    def cis(self, df, writer):
        """Parse the kube-bench JSON file to generate a sheet containing the CIS benchmarks that failed and warned"""

        try:
            # Fail
            df_failed_cis = df[df['status'] == 'FAIL']
            df_failed_cis = df_failed_cis[["status",
                                           "test_number",
                                           "test_desc",
                                           "audit",
                                           "AuditConfig",
                                           "reason",
                                           "remediation"]]
            df_failed_cis.to_excel(
                writer, sheet_name="CIS benchmarks - Fail", index=False)
            self.cis_detected = True
        except: KeyError

        try:
            # Warn
            df_warn_cis = df[df['status'] == 'WARN']
            df_warn_cis = df_warn_cis[["status",
                                       "test_number",
                                       "test_desc",
                                       "audit",
                                       "AuditConfig",
                                       "reason",
                                       "remediation"]]
            df_warn_cis.to_excel(
                writer,
                sheet_name="CIS benchmarks - Warn",
                index=False)
            self.cis_detected = True
        except: KeyError

        try:
            # Pass
            df_pass_cis = df[df['status'] == 'PASS']
            df_pass_cis = df_pass_cis[["status",
                                       "test_number",
                                       "test_desc",
                                       "audit",
                                       "AuditConfig",
                                       "reason",
                                       "remediation"]]
            df_pass_cis.to_excel(
                writer,
                sheet_name="CIS benchmarks - Pass",
                index=False)
        except: KeyError

    def apparmor(self, df, writer):
        try:
            # Apparmor disabled
            df_apparmor_disabled = df[df['AuditResultName']
                                      == 'AppArmorDisabled']
            df_apparmor_disabled = df_apparmor_disabled[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "AnnotationValue", "msg"]]
            df_apparmor_disabled.to_excel(
                writer, sheet_name="Apparmor - Disabled", index=False)

            self.hardened = False
        except: KeyError
          

        try:
            # Apparmor annotation missing
            df_apparmor_missing = df[df['AuditResultName']
                                     == 'AppArmorAnnotationMissing']
            df_apparmor_missing = df_apparmor_missing[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "MissingAnnotation", "msg"]]
            df_apparmor_missing.to_excel(
                writer, sheet_name="Apparmor - Missing", index=False)

            self.hardened = False
        except: KeyError

    def asat(self, df, writer):
        """Automount ServiceAccount Token True And Default SA"""

        try:
            df_automountSA = df[df['AuditResultName'] ==
                                'AutomountServiceAccountTokenTrueAndDefaultSA']
            df_automountSA = df_automountSA[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "Metadata", "msg"]]

            df_automountSA.to_excel(
                writer, sheet_name="Automount SA", index=False)
            self.automount = True
        except: KeyError

    def caps(self, df, writer):
        """Capabilities"""

        try:
            # Missing Caps or Security Context
            df_missing_capabilities_or_seccontext = df[df['AuditResultName']
                                                       == 'CapabilityOrSecurityContextMissing']
            df_missing_capabilities_or_seccontext = df_missing_capabilities_or_seccontext[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "Metadata", "msg"]]
            df_missing_capabilities_or_seccontext.to_excel(
                writer, sheet_name="Caps - missing", index=False)
            self.hardened = False
        except: KeyError

        try:
            # Added Caps
            df_added_capabilities = df[df['AuditResultName']
                                       == 'CapabilityAdded']
            df_added_capabilities = df_added_capabilities[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "Metadata", "msg"]]
            df_added_capabilities.to_excel(
                writer, sheet_name="Caps - Added", index=False)
            self.hardened = False
        except: KeyError

        try:
            # Capability Should Drop All
            df_caps_should_drop = df[df['AuditResultName']
                                     == 'CapabilityShouldDropAll']
            df_caps_should_drop = df_caps_should_drop[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_caps_should_drop.to_excel(
                writer, sheet_name="Caps - Not Drop All", index=False)
            self.hardened = False
        except: KeyError

    def dep_api(self, df, writer):
        """Deprecated API used"""

        try:
            df_dep_api_used = df[df['AuditResultName']
                                        == 'DeprecatedAPIUsed']
            df_dep_api_used = df_dep_api_used[["ResourceName",
                                                             "ResourceKind",
                                                             "IntroducedMajor",
                                                             "IntroducedMinor",
                                                             "DeprecatedMajor",
                                                             "DeprecatedMinor",
                                                             "RemovedMajor",
                                                             "RemovedMinor",
                                                             "ResourceApiVersion",
                                                             "ReplacementGroup",
                                                             "ReplacementKind",
                                                             "msg"]]
            df_dep_api_used.to_excel(
                writer, sheet_name="Deprecated API Used", index=False)
            self.depr_api = True
        except KeyError:
            try:
                df_dep_api_used = df[df['AuditResultName']
                                            == 'DeprecatedAPIUsed']
                df_dep_api_used = df_dep_api_used[["ResourceName",
                                                                 "ResourceKind",
                                                                 "IntroducedMajor",
                                                                 "IntroducedMinor",
                                                                 "DeprecatedMajor",
                                                                 "DeprecatedMinor",
                                                                 "RemovedMajor",
                                                                 "RemovedMinor",
                                                                 "ResourceApiVersion",
                                                                 "msg"]]
                df_dep_api_used.to_excel(
                    writer, sheet_name="Deprecated API Used", index=False)
                self.dprc_api = True
            except: KeyError

    def hostns(self, df, writer):
        """Host namespace"""

        try:
            # Namespace Host PID True
            df_nshost_PID_true = df[df['AuditResultName']
                                    == 'NamespaceHostPIDTrue']
            df_nshost_PID_true = df_nshost_PID_true[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "msg"]]
            df_nshost_PID_true.to_excel(
                writer, sheet_name="Host Namespace - hostPID true", index=False)
            self.hardened = False
        except: KeyError

        try:
            # Namespace Host PID True
            df_ns_hostnetwork_true = df[df['AuditResultName']
                                        == 'NamespaceHostNetworkTrue']
            df_ns_hostnetwork_true = df_ns_hostnetwork_true[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "msg"]]
            df_ns_hostnetwork_true.to_excel(
                writer, sheet_name="Host ns - hostNetwork true", index=False)
            self.hardened = False
        except: KeyError

    def image(self, df, writer):
        # TODO
        return

    def limits(self, df, writer):
        """Limits"""

        try:
            # Limits Not Set
            df_limits_not_set = df[df['AuditResultName'] == 'LimitsNotSet']
            df_limits_not_set = df_limits_not_set[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_limits_not_set.to_excel(
                writer, sheet_name="Limits - Not set", index=False)
            self.limits_set = False
        except: KeyError

        try:
            # Limits CPU Not Set
            df_limits_cpu_not_set = df[df['AuditResultName']
                                       == 'LimitsCPUNotSet']
            df_limits_cpu_not_set = df_limits_cpu_not_set[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_limits_cpu_not_set.to_excel(
                writer, sheet_name="Limits - CPU Not set", index=False)
            self.limits_set = False
        except: KeyError

    def mounts(self, df, writer):
        """Mounted paths"""

        try:
            # Sensitive Paths Mounted
            df_sensitive_paths_mounted = df[df['AuditResultName']
                                            == 'SensitivePathsMounted']
            df_sensitive_paths_mounted = df_sensitive_paths_mounted[["MountName",
                                                                     "MountPath",
                                                                     "MountReadOnly",
                                                                     "MountVolume",
                                                                     "MountVolumeHostPath",
                                                                     "ResourceNamespace",
                                                                     "ResourceKind",
                                                                     "ResourceName",
                                                                     "Container",
                                                                     "msg"]]
            df_sensitive_paths_mounted.to_excel(
                writer, sheet_name="Mounts - Sensitive Paths", index=False)
            self.hardened = False
        except: KeyError

    def netpols(self, df, writer):
        """Network policies"""

        try:
            # Missing Default Deny Ingress And Egress Network Policy
            df_default_deny_missing = df[df['AuditResultName'] ==
                                         'MissingDefaultDenyIngressAndEgressNetworkPolicy']
            df_default_deny_missing = df_default_deny_missing[[
                "ResourceKind", "ResourceName", "msg"]]
            df_default_deny_missing.to_excel(
                writer, sheet_name="NetPol - Missing default deny", index=False)
            self.hardened = False
            print("!!!!!!! REMEMBER TO RUN RBACPOLICE IF HAVE ENOUGH PERMS")
        except: KeyError

        try:
            # AllowAllEgressNetworkPolicyExists
            df_allow_all = df[df['AuditResultName'] ==
                              'AllowAllEgressNetworkPolicyExists']
            df_allow_all = df_allow_all[[
                "ResourceKind", "ResourceName", "msg"]]
            df_allow_all.to_excel(
                writer, sheet_name="NetPol - Allow all", index=False)
            self.hardened = False
            print("!!!!!!! REMEMBER TO RUN RBACPOLICE IF HAVE ENOUGH PERMS")
        except: KeyError

    def nonroot(self, df, writer):
        """Running as"""

        try:
            # Run As Non Root PSC Nil CSC Nil
            df_RunAsNonRootNil = df[df['AuditResultName']
                                    == 'RunAsNonRootPSCNilCSCNil']
            df_RunAsNonRootNil = df_RunAsNonRootNil[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_RunAsNonRootNil.to_excel(
                writer, sheet_name="Non Root - Missing", index=False)
            self.hardened = False
        except: KeyError

        try:
            # Run As User CSC Root
            df_RunAsUserCSCRoot = df[df['AuditResultName']
                                     == 'RunAsUserCSCRoot']
            df_RunAsUserCSCRoot = df_RunAsUserCSCRoot[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_RunAsUserCSCRoot.to_excel(
                writer, sheet_name="Non Root - CSC UID 0", index=False)
            self.hardened = False
        except: KeyError

        try:
            # Run As User PSC Root
            df_RunAsUserPSCRoot = df[df['AuditResultName']
                                     == 'RunAsUserPSCRoot']
            df_RunAsUserPSCRoot = df_RunAsUserPSCRoot[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_RunAsUserPSCRoot.to_excel(
                writer, sheet_name="Non Root - PSC UID 0", index=False)
            self.hardened = False
        except: KeyError

    def privesc(self, df, writer):
        """Privilege escalation"""

        try:
            # Allow Privilege Escalation Nil
            df_AllowPrivilegeEscalationNil = df[df['AuditResultName']
                                                == 'AllowPrivilegeEscalationNil']
            df_AllowPrivilegeEscalationNil = df_AllowPrivilegeEscalationNil[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_AllowPrivilegeEscalationNil.to_excel(
                writer, sheet_name="Privesc - Nil", index=False)
            self.privesc_set = False
        except: KeyError

        try:
            # Allow Privilege Escalation True
            df_AllowPrivilegeEscalationTrue = df[df['AuditResultName']
                                                 == 'AllowPrivilegeEscalationTrue']
            df_AllowPrivilegeEscalationTrue = df_AllowPrivilegeEscalationTrue[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_AllowPrivilegeEscalationTrue.to_excel(
                writer, sheet_name="Privesc - True", index=False)
            self.privesc_set = False
        except: KeyError

    def privileged(self, df, writer):
        """Privileged"""

        try:
            # Privileged Nil
            df_PrivilegedNil = df[df['AuditResultName'] == 'PrivilegedNil']
            df_PrivilegedNil = df_PrivilegedNil[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_PrivilegedNil.to_excel(
                writer, sheet_name="Privileged - Nil", index=False)
            self.privileged_flag = True
            print("!!!!!!! REMEMBER TO RUN RBACPOLICE")
        except: KeyError

        try:
            # Privileged True
            df_PrivilegedTrue = df[df['AuditResultName'] == 'PrivilegedTrue']
            df_PrivilegedTrue = df_PrivilegedTrue[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_PrivilegedTrue.to_excel(
                writer, sheet_name="Privileged - True", index=False)
            self.privileged_flag = True
        except: KeyError

    def rootfs(self, df, writer):
        """Root filesystem"""

        try:
            # ReadOnlyRootFilesystem Nil
            df_ReadOnlyRootFilesystemNil = df[df['AuditResultName']
                                              == 'ReadOnlyRootFilesystemNil']
            df_ReadOnlyRootFilesystemNil = df_ReadOnlyRootFilesystemNil[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_ReadOnlyRootFilesystemNil.to_excel(
                writer, sheet_name="Root FS - ReadOnly Nil", index=False)
            self.hardened = False
        except: KeyError

    def seccomp(self, df, writer):
        "Seccomp profile"

        try:
            # Seccomp Profile Missing
            df_SeccompProfileMissing = df[df['AuditResultName']
                                          == 'SeccompProfileMissing']
            df_SeccompProfileMissing = df_SeccompProfileMissing[[
                "ResourceNamespace", "ResourceKind", "ResourceName", "Container", "msg"]]
            df_SeccompProfileMissing.to_excel(
                writer, sheet_name="Seccomp - Missing", index=False)
            self.hardened = False
        except: KeyError

    def show_status_bar(self, iteration, count, start, size=50):
        """Quick function to show a nice status bar to stderr"""

        x = int(size * iteration / count)
        if iteration != 0:
            remaining = ((time.time() - start) / iteration) * (count - iteration)
            mins, sec = divmod(remaining, 60)
            time_str = f"{mins:02.0f}m {sec:.0f}s"
        else:
            time_str = "N/A"

        print(f"\t Scanned: [{u'█' * x}{' ' * (size-x)}] {iteration}/{count} pods. ETA: {time_str}",
            end='\r',
            file=sys.stderr,
            flush=True)

    def recover_from_aborted_scan(self):
        """Detect if there are any aborted lists"""

        if os.path.isfile(self.pkl_recovery) and os.path.getsize(
                self.pkl_recovery) > 0:
            
            # File exists and has content. Restore it
            with open(self.pkl_recovery, "rb") as recovery_file:
                data = pickle.load(recovery_file)
                scanned_images, vuln_images, vuln_containers, iteration = data
                print(f'{self.cyan_text("[*]")} Restoring data from previous interrupted scan: jumping to pod #{iteration}')
            return scanned_images, vuln_images, vuln_containers, iteration, True

        # Otherwise, return new lists
        return [], [], [], 0, False
    
    def recover_from_aborted_scan_dict(self):
        """Detect if there are any aborted lists"""

        if os.path.isfile(self.pkl_recovery) and os.path.getsize(
                self.pkl_recovery) > 0:
            
            # File exists and has content. Restore it
            with open(self.pkl_recovery, "rb") as recovery_file:
                data = pickle.load(recovery_file)
                images, iteration = data
                print(f'{self.cyan_text("[*]")} Restoring data from previous interrupted scan: jumping to pod #{iteration}')
            return images, iteration, True

        # Otherwise, return new vars
        return {}, 0, False

    def run_trivy(self, image_name):
        """ Run Trivy against the specified image """

        command = f"trivy i -q --scanners vuln --severity HIGH,CRITICAL --format json {image_name}"

        # Start the process
        try:
            process = subprocess.run(
                command.split(" "),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20)
        except subprocess.TimeoutExpired:
            # Return "error" string that will be used to abort further checks of the output
            return "error"

        # Process completed, get the output
        trivy_output = process.stdout.decode('utf-8')
        return json.loads(trivy_output)

    def trivy_parser(self, writer):
        """Run trivy against every image in every container and save output to excel file.
        The function will recover from any crashed instance
        """

        """ Note:
        How to check manually all images. Commands:
        Unique image names: `cat kubectl_all_pods.json | grep '"image":' | sort -u | tr -d '", ' | cut -d ":" -f2,3`
        Total unique count: `cat kubectl_all_pods.json | grep '"image":' | sort -u | tr -d '", ' | cut -d ":" -f2,3 | wc -l | xargs echo "Total images:"`
        """

        # TODO: Would it be quicker to first identify vuln images and then create the dataframe looking for containers which have the vuln images?
        # TODO: refactor function to use dicts instead of lists to make it more efficient

        # Check if no pods were found
        pods = self.pods.get("items", [])
        total_pods = len(pods)
        if total_pods == 0:
            print(f'{self.red_text("[-]")} No pods detected, aborting...\n{self.red_text("[-]")} Please check the permissions of your current role with the following command:\n\t{self.yellow_text("kubectl auth can-i --list")}')
            return

        # Vars needed
        self.pkl_recovery = f"{self.out_path}.kubenumerate_trivy_log_lists.pkl"

        # Create recovery file if doesn't exist
        if not os.path.exists(self.pkl_recovery):
            Path.touch(self.pkl_recovery, 0o644)

        if self.verbosity > 0:
            print(f'{self.yellow_text("[!]")} Launching trivy to scan every unique container image for vulns. This might take a while, please wait...\n{self.yellow_text("[!]")} Known issues: if stuck at 0, run: \n\ttrivy i --download-java-db-only')
            print(f'{self.cyan_text("[*]")} Scanning {self.yellow_text(f"{total_pods}")} pods detected...')

        # Recover from aborted scan, if needed
        scanned_images, vuln_images, vuln_containers, iteration, recovered_file = self.recover_from_aborted_scan()

        # Start progress bar
        start = time.time()
        self.show_status_bar(iteration, total_pods, start)

        # Main loop to go through all images
        for i, pod in enumerate(pods):
            # Check to see if this is a repeating test
            if iteration == total_pods - 1:
                if self.verbosity > 0:
                    print(f'{self.red_text("[-]")} It looks like this test was already run in the past.\nIf you want to redo the assessment, select a different output folder, or run\n\t{self.yellow_text(f"rm {self.pkl_recovery}")}')
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
                containers = pod.get("spec", {}).get("containers", [])
                for container in containers:
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

                        # Vuln image found duplicated, add pod info to vuln
                        # list and skip it
                        if already_found_vulns:
                            if self.verbosity > 1:
                                print(f"Debug: {image_name} already_found_vulns")
                            try:
                                previous_image = [img for img in vuln_containers if img[0] == image_name]
                                new_image = [
                                    image_name,
                                    pod_name,
                                    container_name,
                                    previous_image[0][3],  # crits
                                    previous_image[0][4],  # highs
                                    namespace,
                                ]
                                vuln_containers.append(new_image)
                                continue
                            except UnboundLocalError:
                                # Getting UnboundLocalError when recovering
                                # from previous scan. Ignore.
                                continue

                        # Proceed scanning the image
                        scanned_images.append(image_name)
                        highs, crits = 0, 0
                        try:
                            if self.verbosity > 1:
                                print(f"Scanning image {image_name}")
                            vulnerabilities = self.run_trivy(image_name)
                            if vulnerabilities == "error":
                                continue
                            for result in vulnerabilities.get("Results", []):
                                for vulnerability in result.get(
                                        'Vulnerabilities', []):
                                    if "HIGH" in vulnerability.get('Severity'):
                                        highs += 1

                                    if "CRITICAL" in vulnerability.get(
                                            'Severity'):
                                        crits += 1

                            if highs > 0 or crits > 0:
                                if self.verbosity > 1: 
                                    print("Vuln image detected:", image_name)
                                vuln_images.append(image_name)
                                new_image = [
                                    image_name,
                                    pod_name,
                                    container_name,
                                    crits,
                                    highs,
                                    namespace,
                                ]
                                vuln_containers.append(new_image)
                        except subprocess.CalledProcessError as e:
                            if self.verbosity > 1:
                                print(f"Error scanning trivy: {str(e)}")
                        # Ignore errors for now
                        except KeyError as e:
                            if self.verbosity > 1:
                                print("Key error:", str(e))
            except KeyboardInterrupt:
                if self.verbosity > 0:
                    print(f'\n{self.cyan_text("[*]")} Ctrl+c detected. Recovery file saved to {self.cyan_text(self.pkl_recovery)}...')
                sys.exit(99)
            except json.decoder.JSONDecodeError or ValueError as e:
                if self.verbosity > 1:
                    print(f"Error: {str(e)}")
            except KeyError as e:
                if self.verbosity > 1:
                    print("Key error:", e)
            self.show_status_bar(i + 1, total_pods, start)
        print("\n", flush=True, file=sys.stdout)

        if self.verbosity > 1:
            print("DEBUG: vuln_images:", vuln_containers)
        if len(vuln_containers) != 0:
            self.vuln_image = True
            df = pd.DataFrame(vuln_containers)
            df.columns = [
                "Image",
                "Pod",
                "Container",
                "CRIT",
                "HIGH",
                "Namespace"]
            df.sort_values(by='Image', ascending=True, inplace=True)
            df.to_excel(
                writer,
                sheet_name="Vulnerable Images",
                index=False,
                freeze_panes=(1,0))
        else:
            print(f'{self.green_text("[+]")} No images found containing any high- or critical-risk issues')

    def trivy_parser_dict(self, images_dict, writer):
        """ Parse the extracted dictionary to excel"""

        def count_vulnerable_images_and_pods(images_dictionary):
            """ Nested function that uses multiprocessing to loop through the dictionary """

            num_vulnerable_images = 0
            num_vulnerable_pods = 0

            def count_vulnerable_pods(image_data):
                nonlocal num_vulnerable_pods
                if image_data["vulnerable"]:
                    num_vulnerable_pods += len(image_data["affected_pods"])

            with multiprocessing.Pool() as pool:
                results = pool.map_async(count_vulnerable_pods, images_dictionary.values())
                if self.verbosity > 1:
                    print(f'DEBUG - results: {results}')
                num_vulnerable_images = sum(1 for image_data in images_dictionary.values() if image_data["vulnerable"])

            return num_vulnerable_images, num_vulnerable_pods

        num_vulnerable_images, num_vulnerable_pods = count_vulnerable_images_and_pods(images_dict)
        if self.verbosity > 0:
            print(f"There are {num_vulnerable_images} vulnerable images and {num_vulnerable_pods} vulnerable pods.")

        # Loop over the dict's items and categorise them
        vuln_containers, export = [], False
        for image_name, image_data in images_dict.items():
            if image_data["vulnerable"]:
                export = True
                for pod_data in image_data["affected_pods"]:
                    vuln_containers.append([
                        image_name,                 # Column Image
                        pod_data["pod_name"],       # Column Pod
                        pod_data["container_name"], # Column Container
                        image_data["crits"],        # Column CRITs
                        image_data["highs"],        # Column HIGHs
                        pod_data["namespace"],      # Column Namespace
                    ])

        if export:
            df = pd.DataFrame(vuln_containers, columns=[
                "Image",
                "Pod",
                "Container",
                "CRITs",
                "HIGHs",
                "Namespace",
            ])
            df.sort_values(by='Image', ascending=True, inplace=True)
            df.to_excel(writer, sheet_name="Vulnerable Images", index=False, freeze_panes=(1,0))

    def trivy_extractor(self):
        """ Run trivy against every image in every container and save output to excel file.
        The function will recover from any crashed instance

        returns images_dictionary = {
            image_name (string): {
                "vulnerable": bool,
                "crits": int,
                "highs": int,
                "affected_pods": [
                    {
                        "pod_name": "pod_1" (string),
                        "container_name": "container_1" (string),
                        "namespace": "ns_1" (string),
                    },
                    {
                        "pod_name": "pod_2" (string),
                        "container_name": "container_2" (string),
                        "namespace": "ns_2" (string),
                    },
                ],
            }
        }
        """

        """ Note:
        How to check manually all images for debugging. Commands:
        Unique image names: `cat kubectl_all_pods.json | grep '"image":' | sort -u | tr -d '", ' | cut -d ":" -f2,3`
        Total unique count: `cat kubectl_all_pods.json | grep '"image":' | sort -u | tr -d '", ' | cut -d ":" -f2,3 | wc -l | xargs echo "Total images:"`
        """

        # Check if no pods were found
        pods = self.pods.get("items", [])
        total_pods = len(pods)
        if total_pods == 0:
            print(f'{self.red_text("[-]")} No pods detected, aborting...\n{self.red_text("[-]")} Please check the permissions of your current role with the following command:\n\t{self.yellow_text("kubectl auth can-i --list")}')
            return

        # Create recovery file if doesn't exist
        self.pkl_recovery = f"{self.out_path}.kubenumerate_trivy_log_lists.pkl"
        if not os.path.exists(self.pkl_recovery):
            Path.touch(self.pkl_recovery, 0o644)

        if self.verbosity > 0:
            print(f'{self.yellow_text("[!]")} Launching trivy to scan every unique container image for vulns. This might take a while, please wait...\n{self.yellow_text("[!]")} Known issues: if stuck at 0, run: \n\ttrivy i --download-java-db-only')
            print(f'{self.cyan_text("[*]")} Scanning {self.yellow_text(f"{total_pods}")} pods detected...')

        # Recover from aborted scan, if needed
        images, iteration, recovered_file = self.recover_from_aborted_scan_dict()

        # Start progress bar
        start = time.time()
        self.show_status_bar(iteration, total_pods, start)

        # Main loop to go through all images
        for i, pod in enumerate(pods):
            # Check to see if this is a repeating test
            if iteration == total_pods - 1:
                print(f'{self.red_text("[-]")} It looks like this test was already run in the past.\nIf you want to redo the assessment, select a different output folder, or run\n\t{self.yellow_text(f"rm {self.pkl_recovery}")}')
                break

            # Skip to the recovered point
            if recovered_file and i < iteration:
                continue

            # Save progress with every new loop in case of needing to recover
            # from fatal error
            data = (images, i)
            with open(self.pkl_recovery, "r+b") as recovery_file:
                pickle.dump(data, recovery_file)

            # Check if the image has already been scanned
            try:
                namespace = pod["metadata"]["namespace"]
                pod_name = pod["metadata"]["name"]
                containers = pod.get("spec", {}).get("containers", [])
                for container in containers:
                    image_name = container.get("image")
                    container_name = container.get("name")
                    if image_name:
                        # Don't scan the same image twice
                        already_checked, already_found_vulns = False, False
                        if image_name in images:
                            already_checked = True
                            if images[image_name]["vulnerable"]:
                                already_found_vulns = True

                        # Not vuln but image already checked, skip it
                        if already_checked and not already_found_vulns:
                            if self.verbosity > 1:
                                print("Debug: already checked. Skipping")
                            continue

                        # Vuln image found duplicated, add pod info to vuln list and skip it
                        if already_found_vulns:
                            if self.verbosity > 1:
                                print("Debug: already_found_vulns")
                            images[image_name]["affected_pods"].append(
                                {
                                    "pod_name": pod_name, 
                                    "container_name": container_name, 
                                    "namespace": namespace,
                                }
                            )
                            continue

                        # Proceed scanning the image
                        highs, crits = 0, 0
                        try:
                            if self.verbosity > 1:
                                print(f"Scanning image {image_name}")
                            vulnerabilities = self.run_trivy(image_name)
                            if vulnerabilities == "error":
                                continue
                            for result in vulnerabilities.get("Results", []):
                                for vulnerability in result.get(
                                        'Vulnerabilities', []):
                                    if "HIGH" in vulnerability.get('Severity'):
                                        highs += 1

                                    if "CRITICAL" in vulnerability.get(
                                            'Severity'):
                                        crits += 1

                            if highs > 0 or crits > 0:
                                # Register the new vulnerable image                       
                                images[image_name] = {
                                    "vulnerable": True,
                                    "highs": highs,
                                    "crits": crits,
                                    "affected_pods": [{"pod_name": pod_name, "container_name": container_name, "namespace": namespace}]
                                }
                            else:
                                images[image_name]["vulnerable"] = False
                        except subprocess.CalledProcessError as e:
                            print(f"Error scanning trivy: {str(e)}")
                        # Don't Ignore errors for now
                        except Exception as e:
                            print("ERROR!:", e)
            except KeyboardInterrupt:
                print(f'\n{self.cyan_text("[*]")} Ctrl+c detected. Recovery file saved to {self.cyan_text(self.pkl_recovery)}...')
                sys.exit(99)
            except json.decoder.JSONDecodeError or ValueError as e:
                print(f"Error: {str(e)}")
            except KeyError as e:
                print("Key error": str(e))

            self.show_status_bar(i + 1, total_pods, start)
        print("\n", flush=True, file=sys.stdout)

        return images

    def raise_issues(self):
        """ Suggest what issues might be present """

        print(f'{self.green_text("[+]")} Suggested findings detected:')

        # Containers Not Hardened
        if not self.hardened:
            print(f'\t{self.red_text("[!]")} Containers Not Hardened')

        # Containers Automount Service Account Token
        if self.automount:
            print(f'\t{self.red_text("[!]")} Containers Automount Service Account Token')

        # Vulnerable Container Images Pulled From Third-Party Repositories
        if self.vuln_image:
            print(f'\t{self.red_text("[!]")} Vulnerable Container Images Pulled From Third-Party Repositories')

        # Containers Allowing Privilege Escalation
        if self.privileged_flag:
            print(f'\t{self.red_text("[!]")} Containers Allowing Privilege Escalation')

        # CIS Benchmarks
        if self.cis_detected:
            print(f'\t{self.red_text("[!]")} CIS Benchmarks')

        # #TODO:to determine
        # if self.depr_api:

        # CPU usage
        if not self.limits_set:
            print(f'\t{self.red_text("[!]")} CPU usage')


def main():
    instance = Kubenumerate()
    instance.Run()


if __name__ == "__main__":
    main()