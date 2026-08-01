#!/usr/bin/env python3
"""
Tests for auditing initContainers and ephemeralContainers, not just spec.containers.

Ephemeral containers are debug containers injected into a running pod; the API forbids `resources` on
them (see EphemeralContainerCommon in k8s.io/api/core/v1), so resource-limit checks must not apply, but
securityContext and volumeMounts are permitted and must be audited like any other container.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kubenumerate import Kubenumerate  # noqa: E402


def build_pod(spec, name="test-pod", namespace="default"):
    return {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def run_audit(tmp_path, items, cluster_version="1.36.0"):
    out_dir = tmp_path / "kubectl"
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / "pods.json", "w") as f:
        json.dump({"items": items}, f)
    kube = Kubenumerate(
        cluster_version=cluster_version,
        dry_run=False,
        kubectl_output_path=str(out_dir),
        verbosity=0,
    )
    return kube.generate_kubeaudit_equivalent_df_from_kubectl()


def findings_for(df, container_substring):
    """All result names whose Container cell contains the given substring."""
    matched = df[df["Container"].astype(str).str.contains(container_substring, na=False)]
    return list(matched["AuditResultName"])


class TestInitContainersAreAudited:
    def test_privileged_init_container_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [{"name": "setup", "securityContext": {"privileged": True}}],
                    }
                )
            ],
        )
        assert "PrivilegedTrue" in findings_for(df, "setup")

    def test_init_container_proc_mount_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [{"name": "setup", "securityContext": {"procMount": "Unmasked"}}],
                    }
                )
            ],
        )
        assert "ProcMountUnmasked" in findings_for(df, "setup")

    def test_init_container_is_labelled_in_the_container_column(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [{"name": "setup"}]})],
        )
        assert any("setup (init)" == c for c in df["Container"].dropna())

    def test_init_container_has_container_type(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [{"name": "setup"}]})],
        )
        row = df[df["Container"] == "setup (init)"].iloc[0]
        assert row["ContainerType"] == "initContainer"

    def test_init_containers_still_get_resource_limit_findings(self, tmp_path):
        """Unlike ephemeral containers, initContainers do accept resources."""
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [{"name": "setup"}]})],
        )
        assert "LimitsNotSet" in findings_for(df, "setup")


class TestEphemeralContainersAreAudited:
    def test_privileged_ephemeral_container_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "ephemeralContainers": [{"name": "debugger", "securityContext": {"privileged": True}}],
                    }
                )
            ],
        )
        assert "PrivilegedTrue" in findings_for(df, "debugger")

    def test_ephemeral_container_proc_mount_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "ephemeralContainers": [{"name": "debugger", "securityContext": {"procMount": "Unmasked"}}],
                    }
                )
            ],
        )
        assert "ProcMountUnmasked" in findings_for(df, "debugger")

    def test_ephemeral_container_is_labelled_in_the_container_column(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "ephemeralContainers": [{"name": "debugger"}]})],
        )
        assert any("debugger (ephemeral)" == c for c in df["Container"].dropna())

    def test_ephemeral_container_has_container_type(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "ephemeralContainers": [{"name": "debugger"}]})],
        )
        row = df[df["Container"] == "debugger (ephemeral)"].iloc[0]
        assert row["ContainerType"] == "ephemeralContainer"

    def test_ephemeral_containers_get_no_resource_limit_findings(self, tmp_path):
        """The API forbids `resources` on ephemeral containers, so flagging it would be a false positive."""
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "ephemeralContainers": [{"name": "debugger"}]})],
        )
        results = findings_for(df, "debugger")
        assert "LimitsNotSet" not in results
        assert "LimitsCPUNotSet" not in results

    def test_ephemeral_container_sensitive_mounts_are_still_checked(self, tmp_path):
        """volumeMounts are permitted on ephemeral containers, so the mount check must still run."""
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "ephemeralContainers": [
                            {"name": "debugger", "volumeMounts": [{"name": "host", "mountPath": "/etc/shadow"}]}
                        ],
                    }
                )
            ],
        )
        assert "SensitivePathsMounted" in findings_for(df, "debugger")


class TestRegularContainersUnchanged:
    def test_regular_container_name_is_not_annotated(self, tmp_path):
        df = run_audit(tmp_path, [build_pod({"containers": [{"name": "app"}]})])
        assert "app" in list(df["Container"].dropna())
        assert not any("(init)" in str(c) or "(ephemeral)" in str(c) for c in df["Container"].dropna())

    def test_regular_container_has_container_type(self, tmp_path):
        df = run_audit(tmp_path, [build_pod({"containers": [{"name": "app"}]})])
        row = df[df["Container"] == "app"].iloc[0]
        assert row["ContainerType"] == "container"

    def test_regular_container_still_gets_limit_findings(self, tmp_path):
        df = run_audit(tmp_path, [build_pod({"containers": [{"name": "app"}]})])
        assert "LimitsNotSet" in findings_for(df, "app")


class TestUserNamespaceAcrossContainerTypes:
    def test_user_namespace_mitigation_applies_to_init_containers(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "hostUsers": False,
                        "containers": [{"name": "app"}],
                        "initContainers": [{"name": "setup", "securityContext": {"runAsUser": 0}}],
                    }
                )
            ],
        )
        row = df[(df["Container"] == "setup (init)") & (df["AuditResultName"] == "RunAsUserCSCRoot")].iloc[0]
        assert bool(row["UserNamespaced"]) is True

    def test_recommendation_raised_for_pod_with_only_init_containers(self, tmp_path):
        df = run_audit(tmp_path, [build_pod({"initContainers": [{"name": "setup"}]})])
        assert "UserNamespaceNotEnabled" in list(df["AuditResultName"])


class TestPodLevelFindingsAreNotDuplicated:
    def test_automount_finding_raised_once_per_pod(self, tmp_path):
        """It is a pod-level property, so extra containers must not multiply it."""
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "a"}, {"name": "b"}],
                        "initContainers": [{"name": "setup"}],
                        "ephemeralContainers": [{"name": "debugger"}],
                    }
                )
            ],
        )
        names = list(df["AuditResultName"])
        assert names.count("AutomountServiceAccountTokenTrueAndDefaultSA") == 1


class TestContainerTypesReachTheExcelReport:
    def test_init_and_ephemeral_containers_are_labelled_in_the_workbook(self, tmp_path):
        import pandas as pd
        from openpyxl import load_workbook

        out_dir = tmp_path / "kubectl"
        out_dir.mkdir()
        items = [
            build_pod(
                {
                    "containers": [{"name": "app", "securityContext": {"privileged": True}}],
                    "initContainers": [{"name": "setup", "securityContext": {"privileged": True}}],
                    "ephemeralContainers": [{"name": "debugger", "securityContext": {"privileged": True}}],
                }
            )
        ]
        with open(out_dir / "pods.json", "w") as f:
            json.dump({"items": items}, f)

        excel_file = tmp_path / "report.xlsx"
        kube = Kubenumerate(
            cluster_version="1.36.0",
            dry_run=False,
            kubectl_output_path=str(out_dir),
            excel_file=str(excel_file),
            verbosity=0,
        )
        df = kube.generate_kubeaudit_equivalent_df_from_kubectl()
        with pd.ExcelWriter(str(excel_file), engine="xlsxwriter", mode="w") as writer:
            kube.privileged(df, writer)
        workbook = load_workbook(str(excel_file))
        text = "\n".join(
            " ".join(str(cell) for cell in row if cell is not None) for row in workbook["Privileged - True"].values
        )
        assert "app" in text
        assert "setup (init)" in text
        assert "debugger (ephemeral)" in text


class TestSidecarContainersAreDistinguished:
    """An initContainer with restartPolicy: Always runs for the pod's whole lifetime (KEP-753).

    That makes its security posture closer to an app container than to a short-lived init container,
    so it must be reported distinctly rather than lumped in with initContainers.
    """

    @staticmethod
    def sidecar(name="proxy", **extra):
        return {"name": name, "restartPolicy": "Always", **extra}

    def test_sidecar_has_its_own_container_type(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [self.sidecar()]})],
        )
        row = df[df["Container"] == "proxy (sidecar)"].iloc[0]
        assert row["ContainerType"] == "sidecarContainer"

    def test_sidecar_is_labelled_distinctly_from_init(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [{"name": "setup"}, self.sidecar()],
                    }
                )
            ],
        )
        labels = set(df["Container"].dropna())
        assert "proxy (sidecar)" in labels
        assert "setup (init)" in labels
        assert "proxy (init)" not in labels

    def test_ordinary_init_container_is_not_classed_as_sidecar(self, tmp_path):
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [{"name": "setup"}]})],
        )
        assert "sidecarContainer" not in set(df["ContainerType"].dropna())

    def test_init_container_with_other_restart_policy_is_not_a_sidecar(self, tmp_path):
        """Only restartPolicy: Always creates the sidecar lifecycle."""
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [{"name": "setup", "restartPolicy": "OnFailure"}],
                    }
                )
            ],
        )
        row = df[df["Container"] == "setup (init)"].iloc[0]
        assert row["ContainerType"] == "initContainer"

    def test_privileged_sidecar_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [self.sidecar(securityContext={"privileged": True})],
                    }
                )
            ],
        )
        assert "PrivilegedTrue" in findings_for(df, "proxy")

    def test_sidecar_proc_mount_is_flagged(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "containers": [{"name": "app"}],
                        "initContainers": [self.sidecar(securityContext={"procMount": "Unmasked"})],
                    }
                )
            ],
        )
        assert "ProcMountUnmasked" in findings_for(df, "proxy")

    def test_sidecar_still_gets_resource_limit_findings(self, tmp_path):
        """Sidecars accept resources, and hold them for the pod's whole lifetime."""
        df = run_audit(
            tmp_path,
            [build_pod({"containers": [{"name": "app"}], "initContainers": [self.sidecar()]})],
        )
        assert "LimitsNotSet" in findings_for(df, "proxy")

    def test_user_namespace_mitigation_applies_to_sidecars(self, tmp_path):
        df = run_audit(
            tmp_path,
            [
                build_pod(
                    {
                        "hostUsers": False,
                        "containers": [{"name": "app"}],
                        "initContainers": [self.sidecar(securityContext={"runAsUser": 0})],
                    }
                )
            ],
        )
        row = df[(df["Container"] == "proxy (sidecar)") & (df["AuditResultName"] == "RunAsUserCSCRoot")].iloc[0]
        assert bool(row["UserNamespaced"]) is True
