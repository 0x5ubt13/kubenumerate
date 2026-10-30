"""Project-scoped security review: observations about namespaced configuration.

Covers namespace Pod Security Admission labels, namespaced RBAC, service-account token settings, Service and Ingress
exposure, ResourceQuota/LimitRange/PVC/PodDisruptionBudget configuration, Pod-versus-template drift, and Confluent
Platform custom resources.

Everything here is pure: parsed Kubernetes JSON objects in, finding dicts out. Findings describe declared or observed
configuration. A missing field is reported as "not set"; nothing is a verdict, and no Secret data is read.
"""

from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

# Permissions worth reviewing in a namespace: (audit name, resources, verbs)
RBAC_RISKS: List[Tuple[str, Set[str], Set[str], Set[str]]] = [
    # (audit name, API groups, resources, verbs). "" is the core API group
    ("RoleSecretRead", {""}, {"secrets"}, {"get", "list", "watch"}),
    ("RolePodCreate", {""}, {"pods"}, {"create"}),
    ("RolePodsExec", {""}, {"pods/exec", "pods/attach"}, {"create"}),
    (
        "RoleWorkloadCreate",
        {"apps", "batch"},
        {"deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"},
        {"create"},
    ),
    ("RoleServiceAccountTokenCreate", {""}, {"serviceaccounts/token"}, {"create"}),
    (
        "RoleModifiesRBAC",
        {"rbac.authorization.k8s.io"},
        {"roles", "rolebindings"},
        {"create", "update", "patch", "delete"},
    ),
    ("RoleEscalateBind", {"rbac.authorization.k8s.io"}, {"roles", "clusterroles"}, {"bind", "escalate"}),
    ("RoleImpersonation", {""}, {"users", "groups", "serviceaccounts", "uids"}, {"impersonate"}),
]

# Namespace RBAC audit names, reused for ClusterRoles with a Cluster prefix
RBAC_AUDITS = [audit for audit, _, _, _ in RBAC_RISKS] + ["RoleWildcardPermission"]
# Identities that cover everyone. system:anonymous is bound as a User subject; the others are Groups.
BROAD_IDENTITIES = {"system:authenticated", "system:unauthenticated", "system:anonymous", "system:serviceaccounts"}
BROAD_BUILTIN_ROLES = {"cluster-admin", "admin", "edit"}
POD_TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
REPLICATED_KINDS = {"Deployment", "StatefulSet"}
CONFLUENT_API_PREFIX = "platform.confluent.io/"
CONFLUENT_COMPONENTS = {"controlcenter", "kafkarestproxy", "connect", "schemaregistry"}
PRIVILEGED_CONFLUENT_ROLES = {"SystemAdmin", "ClusterAdmin"}
NOT_SET = "not set"
NOT_ASSESSED_CLUSTER_SCOPED = "cluster-scoped evidence excluded by namespace/project scope"

# Audit name -> one-line recommendation shown next to each observation in the report
RECOMMENDATIONS: Dict[str, str] = {
    "PodSecurityAdmissionLabels": "Review the enforce, audit and warn labels together.",
    "PSAEnforceNotSet": "Set pod-security.kubernetes.io/enforce, or confirm another control enforces pod security here.",
    "PSAEnforcePrivileged": "Use baseline or restricted for enforce unless privileged pods are required.",
    "RoleWildcardPermission": "Replace wildcard resources or verbs with the explicit set the workloads need.",
    "RoleSecretRead": "Limit secret read access to the identities that need it, by name where possible.",
    "RolePodCreate": "Confirm the identities allowed to create pods need that access.",
    "RolePodsExec": "Remove pods/exec and pods/attach unless interactive access is a documented requirement.",
    "RoleWorkloadCreate": "Confirm workload creation is restricted to deployment identities.",
    "RoleServiceAccountTokenCreate": "Remove serviceaccounts/token create unless token minting is required.",
    "RoleModifiesRBAC": "Remove permission to change roles and bindings from non-administrative identities.",
    "RoleEscalateBind": "Remove bind and escalate; they allow granting permissions the subject does not hold.",
    "RoleImpersonation": "Remove impersonation unless a specific delegated workflow requires it.",
    "RoleBindingConfigured": "Confirm the subjects and the referenced role are expected.",
    "BindingReferencesClusterRole": "Review the ClusterRole directly with cluster-level access; it is not assessed here.",
    "BindingToBroadBuiltInRole": "Confirm the broad built-in role is intended for these subjects.",
    "BindingToBroadGroup": "Avoid binding to system groups that cover every identity.",
    "BindingToRiskyRole": "Review the risky permissions of the referenced Role above.",
    "ServiceConfigured": "Confirm the service type is intended. Configuration only.",
    "ServiceLoadBalancer": "Confirm the service should be exposed through a load balancer, and restrict its source ranges.",
    "ServiceNodePort": "Confirm the NodePort exposure is intended and restrict it at the network layer.",
    "IngressConfigured": "Confirm the hosts are intended. Configuration only.",
    "IngressWithoutTLS": "Declare spec.tls for the hosts, or confirm TLS is terminated elsewhere.",
    "IngressHostWithoutTLS": "Add a TLS entry covering these hosts.",
    "ServiceAccountTokenAutomounted": "Set automountServiceAccountToken: false unless the pods need the API.",
    "PodTokenAutomountExplicit": "Remove the pod-level automount: true, or use a dedicated service account.",
    "PodDiffersFromTemplate": "Check whether the Pod was changed by admission or the template changed since it was created.",
    "ResourceQuotaConfigured": "Confirm the quota covers the resources this project needs.",
    "LimitRangeConfigured": "Confirm default requests and limits are set for the project's workloads.",
    "NamespaceWithoutResourceQuota": "Consider a ResourceQuota to bound the namespace's resource use.",
    "NamespaceWithoutLimitRange": "Consider a LimitRange so containers get default requests and limits.",
    "PVCConfigured": "Confirm the requested size, access modes and storage class are intended. PVs are not queried.",
    "PVCStorageClassNotSet": "Set storageClassName explicitly rather than relying on a cluster default.",
    "PVCReadWriteMany": "Confirm the shared read-write volume is intended and the storage backend supports it.",
    "PDBConfigured": "Confirm the budget protects the workload as intended.",
    "PDBAllowsAllDisruption": "Set minAvailable or a maxUnavailable below 100%.",
    "NamespaceWithoutPDB": "Consider a PodDisruptionBudget for replicated workloads in this namespace.",
    "ConfluentKafkaListeners": "Confirm listener types, ports, authentication and TLS match the intended design.",
    "ConfluentListenerAuthNotDeclared": "Declare an authentication type for every listener.",
    "ConfluentListenerTLSNotDeclared": "Enable TLS on every listener, or confirm it is terminated elsewhere.",
    "ConfluentTopicConfigured": "Confirm partition and replication settings are intended.",
    "ConfluentTopicReplicationOne": "Use a replication factor above 1 for topics that must survive a broker loss.",
    "ConfluentComponentConfigured": "Confirm the component's authentication and TLS settings. Secret references are not read.",
    "ConfluentComponentAuthNotDeclared": "Declare an authentication type for this component.",
    "ConfluentComponentTLSNotDeclared": "Enable TLS for this component, or confirm it is terminated elsewhere.",
    "ConfluentComponentKafkaAuthNotDeclared": "Declare the Kafka client authentication under dependencies.kafka.authentication.",
    "ConfluentRoleBindingConfigured": "Confirm the role and resource patterns are intended. Principal names are omitted.",
    "ConfluentPrivilegedRoleBinding": "Restrict privileged Confluent roles to administrators.",
    "WebhookConfigured": "Review the webhook's scope, failure policy and destination.",
    "WebhookFailurePolicyIgnore": "Use failurePolicy: Fail for webhooks that enforce security controls.",
    "WebhookExternalURL": "Confirm the external endpoint is trusted and reachable only as intended.",
    "NodeKubeletVersion": "Keep kubelet versions current and check the node against the vendor's patch level.",
    "NodeKubeletVersionSkew": "Bring nodes onto one kubelet version; skew means some nodes lag security fixes.",
    "ClusterRoleBindingConfigured": "Confirm the subjects and the ClusterRole are expected.",
    "ClusterBindingToClusterAdmin": "Limit cluster-admin to named administrators.",
    "ClusterBindingToBroadGroup": "Avoid binding cluster roles to system groups that cover every identity.",
    "ClusterBindingToRiskyRole": "Review the risky permissions of the referenced ClusterRole.",
    "OpenShiftPodPermissiveSCC": "Run the workload under restricted-v2 unless it genuinely needs the permissions.",
    "OpenShiftSCCAllowsPrivileged": "Remove privileged from the SCC unless a named workload requires it.",
    "OpenShiftSCCAllowsHostAccess": "Remove host namespace and host path access from the SCC.",
    "OpenShiftSCCRunAsAny": "Use MustRunAsRange or MustRunAsNonRoot instead of RunAsAny.",
    "OpenShiftSCCGrantedBroadly": "Do not grant permissive SCCs to system:authenticated or other broad groups.",
    "OpenShiftRouteWithoutTLS": "Add TLS termination to the Route.",
    "OpenShiftRouteAllowsInsecure": "Set insecureEdgeTerminationPolicy to Redirect or None.",
}
# Cluster-wide variants of the namespace RBAC advice
RECOMMENDATIONS.update({f"Cluster{audit}": f"{RECOMMENDATIONS[audit]} Applies cluster-wide." for audit in RBAC_AUDITS})

# Report sheets: (title, subtitle, sheet name, audit names). Every audit name must appear in exactly one section.
REVIEW_SECTIONS: List[Tuple[str, str, str, List[str]]] = [
    (
        "Namespace - Pod Security Admission labels",
        "Pod Security Admission labels per selected namespace/project. A missing label is an observation, not proof that "
        "no other control applies.",
        "PSA labels",
        ["PodSecurityAdmissionLabels", "PSAEnforceNotSet", "PSAEnforcePrivileged"],
    ),
    (
        "RBAC - Namespaced Roles",
        "Risky permissions granted by Roles in the selected namespaces. ClusterRole rules are not assessed here.",
        "RBAC - Roles",
        [
            "RoleWildcardPermission",
            "RoleSecretRead",
            "RolePodCreate",
            "RolePodsExec",
            "RoleWorkloadCreate",
            "RoleServiceAccountTokenCreate",
            "RoleModifiesRBAC",
            "RoleEscalateBind",
            "RoleImpersonation",
        ],
    ),
    (
        "RBAC - RoleBindings",
        "How Roles are bound in the selected namespaces. Subject names are omitted; references are reported as found.",
        "RBAC - Bindings",
        [
            "RoleBindingConfigured",
            "BindingReferencesClusterRole",
            "BindingToBroadBuiltInRole",
            "BindingToBroadGroup",
            "BindingToRiskyRole",
        ],
    ),
    (
        "Service exposure",
        "Service types, ports and selectors. This shows configuration only, not whether a service is reachable.",
        "Service exposure",
        ["ServiceConfigured", "ServiceLoadBalancer", "ServiceNodePort"],
    ),
    (
        "Ingress TLS",
        "Ingress hosts and TLS configuration. This shows configuration only.",
        "Ingress TLS",
        ["IngressConfigured", "IngressWithoutTLS", "IngressHostWithoutTLS"],
    ),
    (
        "ServiceAccount tokens",
        "Whether service accounts and pods mount API tokens, and where a pod overrides the service account setting.",
        "SA tokens",
        ["ServiceAccountTokenAutomounted", "PodTokenAutomountExplicit"],
    ),
    (
        "Pod versus workload template",
        "Pods whose security-relevant spec differs from the template of their controller. Observation only.",
        "Template drift",
        ["PodDiffersFromTemplate"],
    ),
    (
        "Resource controls",
        "ResourceQuota, LimitRange, PVC and PodDisruptionBudget configuration. PersistentVolumes are not queried.",
        "Resource controls",
        [
            "ResourceQuotaConfigured",
            "LimitRangeConfigured",
            "NamespaceWithoutResourceQuota",
            "NamespaceWithoutLimitRange",
            "PVCConfigured",
            "PVCStorageClassNotSet",
            "PVCReadWriteMany",
            "PDBConfigured",
            "PDBAllowsAllDisruption",
            "NamespaceWithoutPDB",
        ],
    ),
    (
        "Confluent - Kafka and topics",
        "Declared Kafka listener and topic configuration. Secret references are not read. Declared, not tested.",
        "Confluent - Kafka",
        [
            "ConfluentKafkaListeners",
            "ConfluentListenerAuthNotDeclared",
            "ConfluentListenerTLSNotDeclared",
            "ConfluentTopicConfigured",
            "ConfluentTopicReplicationOne",
        ],
    ),
    (
        "Confluent - Components and role bindings",
        "Declared configuration of Confluent components and role bindings. Principal names are omitted.",
        "Confluent - Components",
        [
            "ConfluentComponentConfigured",
            "ConfluentComponentAuthNotDeclared",
            "ConfluentComponentTLSNotDeclared",
            "ConfluentComponentKafkaAuthNotDeclared",
            "ConfluentRoleBindingConfigured",
            "ConfluentPrivilegedRoleBinding",
        ],
    ),
]

# Cluster-scoped sections: only in cluster-wide runs
CLUSTER_SECTIONS: List[Tuple[str, str, str, List[str]]] = [
    (
        "Cluster RBAC - ClusterRoles",
        "Risky permissions granted by ClusterRoles. Roles named system:* are Kubernetes defaults and are not reviewed.",
        "Cluster RBAC - Roles",
        ["Cluster" + audit for audit in RBAC_AUDITS],
    ),
    (
        "Cluster RBAC - ClusterRoleBindings",
        "How ClusterRoles are bound cluster-wide. Subject names are omitted. system:* bindings are not reviewed.",
        "Cluster RBAC - Bindings",
        [
            "ClusterRoleBindingConfigured",
            "ClusterBindingToClusterAdmin",
            "ClusterBindingToBroadGroup",
            "ClusterBindingToRiskyRole",
        ],
    ),
    (
        "Admission webhooks",
        "Validating and mutating webhooks: failure policy and external endpoints. Configuration only.",
        "Admission webhooks",
        ["WebhookConfigured", "WebhookFailurePolicyIgnore", "WebhookExternalURL"],
    ),
    (
        "Nodes",
        "Kubelet version reported by each node, and whether the versions differ across nodes.",
        "Nodes",
        ["NodeKubeletVersion", "NodeKubeletVersionSkew"],
    ),
]

# OpenShift sections: any mode. The SCC definitions are cluster-scoped, so they only appear in cluster-wide runs
OPENSHIFT_SECTIONS: List[Tuple[str, str, str, List[str]]] = [
    (
        "OpenShift - Pods admitted under permissive SCCs",
        "SecurityContextConstraints (SCCs) decide what a pod may do. Pods admitted under privileged, anyuid, "
        "hostnetwork, hostaccess or similar SCCs run with more privilege than the restricted-v2 default.",
        "OpenShift - Pod SCC",
        ["OpenShiftPodPermissiveSCC"],
    ),
    (
        "OpenShift - Routes without TLS",
        "Routes that serve plain HTTP or allow an insecure fallback to HTTP at the router.",
        "OpenShift - Routes",
        ["OpenShiftRouteWithoutTLS", "OpenShiftRouteAllowsInsecure"],
    ),
]
OPENSHIFT_CLUSTER_SECTIONS: List[Tuple[str, str, str, List[str]]] = [
    (
        "OpenShift - Permissive SCC definitions",
        "SCCs that allow privileged containers, host namespaces or host paths, or that run as any UID, and whether they "
        "are granted to broad groups such as system:authenticated.",
        "OpenShift - SCC definitions",
        [
            "OpenShiftSCCAllowsPrivileged",
            "OpenShiftSCCAllowsHostAccess",
            "OpenShiftSCCRunAsAny",
            "OpenShiftSCCGrantedBroadly",
        ],
    ),
]


def selected_sections(review: bool, cluster: bool, openshift: bool) -> List[Tuple[str, str, str, List[str]]]:
    """Sections this run produces. A section appears only when its checks ran: cluster-scoped checks need a cluster-wide
    run, and the review can be switched off"""
    chosen: List[Tuple[str, str, str, List[str]]] = []
    if review:
        chosen += REVIEW_SECTIONS
        if cluster:
            chosen += CLUSTER_SECTIONS
    if openshift:
        chosen += OPENSHIFT_SECTIONS
        if cluster:
            chosen += OPENSHIFT_CLUSTER_SECTIONS
    return chosen


def _grants(granted: Set[str], wanted: Set[str]) -> bool:
    """A wildcard grants everything; otherwise any overlap counts"""
    return "*" in granted or bool(granted & wanted)


def _describe(values: Set[str]) -> str:
    return ", ".join(sorted(values))


def _describe_groups(groups: Set[str]) -> str:
    return ", ".join(sorted(group or "core" for group in groups)) or "no API group"


def rbac_rule_risks(rules: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Risky permissions the rules grant, as {audit name: [detail, ...]}.

    A rule matches only through its apiGroups, as the API server does: a rule with no apiGroups grants nothing.
    """
    risks: Dict[str, List[str]] = {}
    for rule in rules or []:
        groups = set(rule.get("apiGroups", []))
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        detail = f"{_describe_groups(groups)} {_describe(resources)}: {_describe(verbs)}"
        if "*" in groups or "*" in resources or "*" in verbs:
            risks.setdefault("RoleWildcardPermission", []).append(detail)
        for audit, risk_groups, risk_resources, risk_verbs in RBAC_RISKS:
            if _grants(groups, risk_groups) and _grants(resources, risk_resources) and _grants(verbs, risk_verbs):
                risks.setdefault(audit, []).append(detail)
    return {audit: sorted(set(details)) for audit, details in risks.items()}


def pod_spec_of(item: Dict[str, Any]) -> Dict[str, Any]:
    """The Pod spec of a Pod, or the template spec of a workload controller"""
    spec = item.get("spec", {}) or {}
    if item.get("kind") == "Pod":
        return spec
    return (spec.get("template", {}) or {}).get("spec", {}) or {}


def _controller_owner(metadata: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    for ref in metadata.get("ownerReferences", []) or []:
        if ref.get("controller"):
            return ref.get("kind", ""), ref.get("name", "")
    return None


def _make(audit: str, msg: str, namespace: str, kind: str, name: str) -> Dict[str, Any]:
    return {
        "AuditResultName": audit,
        "ResourceNamespace": namespace,
        "ResourceKind": kind,
        "ResourceName": name,
        "msg": msg,
    }


def project_findings(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings for one object, from the per-object checks"""
    kind = item.get("kind", "")
    metadata = item.get("metadata", {}) or {}
    namespace = metadata.get("namespace", "")
    name = metadata.get("name", "")
    spec = item.get("spec", {}) or {}
    findings: List[Dict[str, Any]] = []

    def add(audit: str, msg: str) -> None:
        # A Namespace is its own namespace: the report attributes its labels to the namespace itself
        scope = name if kind == "Namespace" else namespace
        findings.append(_make(audit, msg, scope, kind, name))

    if kind == "Namespace":
        labels = metadata.get("labels", {}) or {}
        modes = {
            mode: labels.get(f"pod-security.kubernetes.io/{mode}", NOT_SET) for mode in ("enforce", "audit", "warn")
        }
        add("PodSecurityAdmissionLabels", f"enforce={modes['enforce']}; audit={modes['audit']}; warn={modes['warn']}.")
        if modes["enforce"] == NOT_SET:
            add(
                "PSAEnforceNotSet",
                "No pod-security.kubernetes.io/enforce label. Other controls, such as OpenShift SCCs, may still apply.",
            )
        if modes["enforce"] == "privileged":
            add("PSAEnforcePrivileged", "enforce is privileged, so Pod Security Admission does not restrict pods here.")

    elif kind == "Role":
        for audit, details in rbac_rule_risks(item.get("rules", [])).items():
            add(audit, f"Role grants {'; '.join(details)}.")

    elif kind == "RoleBinding":
        ref = item.get("roleRef", {}) or {}
        ref_kind, ref_name = ref.get("kind", ""), ref.get("name", "")
        subjects = item.get("subjects", []) or []
        counts = Counter(subject.get("kind", "unknown") for subject in subjects)
        summary = ", ".join(f"{count} {subject_kind}" for subject_kind, count in sorted(counts.items())) or "none"
        add(
            "RoleBindingConfigured", f"Binds {ref_kind} '{ref_name}' to subjects: {summary}. Subject names are omitted."
        )
        if ref_kind == "ClusterRole":
            add(
                "BindingReferencesClusterRole",
                f"References ClusterRole '{ref_name}'. Its rules are not assessed in namespace/project mode; only the "
                "reference is reported.",
            )
        if ref_name in BROAD_BUILTIN_ROLES:
            add(
                "BindingToBroadBuiltInRole",
                f"References the built-in role '{ref_name}', which is broad. Reported from the name; contents not inspected.",
            )
        groups = sorted({s.get("name", "") for s in subjects if s.get("name") in BROAD_IDENTITIES})
        if groups:
            add("BindingToBroadGroup", f"Grants '{ref_name}' to broad subject(s): {', '.join(groups)}.")

    elif kind == "Service":
        service_type = spec.get("type", "ClusterIP")
        ports = ", ".join(f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in spec.get("ports", []) or []) or "none"
        selector = "selector set" if spec.get("selector") else "no selector"
        audit = {"LoadBalancer": "ServiceLoadBalancer", "NodePort": "ServiceNodePort"}.get(
            service_type, "ServiceConfigured"
        )
        add(
            audit,
            f"Service type {service_type}, ports {ports}, {selector}. Configuration only; reachability is not tested.",
        )

    elif kind == "Ingress":
        hosts = [rule.get("host", "<any host>") for rule in spec.get("rules", []) or []]
        tls_entries = spec.get("tls", []) or []
        tls_hosts = {host for entry in tls_entries for host in entry.get("hosts", []) or []}
        add(
            "IngressConfigured",
            f"Hosts {', '.join(hosts) or 'none'}; TLS entries {len(tls_entries)}. Configuration only.",
        )
        if not tls_entries:
            add(
                "IngressWithoutTLS",
                f"No spec.tls for hosts {', '.join(hosts) or 'none'}. TLS may still be configured elsewhere, for example "
                "by the controller.",
            )
        else:
            uncovered = [host for host in hosts if host not in tls_hosts]
            if uncovered:
                add("IngressHostWithoutTLS", f"Hosts without a matching TLS entry: {', '.join(uncovered)}.")

    elif kind == "ServiceAccount":
        automount = item.get("automountServiceAccountToken")
        if automount is not False:
            add(
                "ServiceAccountTokenAutomounted",
                f"automountServiceAccountToken is {'true' if automount else NOT_SET}. Pods using this account receive its "
                "token unless they opt out.",
            )

    elif kind == "ResourceQuota":
        hard = sorted((spec.get("hard") or {}).keys())
        add("ResourceQuotaConfigured", f"Hard limits on: {', '.join(hard) or 'none'}.")

    elif kind == "LimitRange":
        types = sorted({limit.get("type", "unknown") for limit in spec.get("limits", []) or []})
        add("LimitRangeConfigured", f"Limit types: {', '.join(types) or 'none'}.")

    elif kind == "PersistentVolumeClaim":
        storage = ((spec.get("resources") or {}).get("requests") or {}).get("storage", NOT_SET)
        access_modes = spec.get("accessModes", []) or []
        storage_class = spec.get("storageClassName")
        add(
            "PVCConfigured",
            f"Requests {storage}; access modes {', '.join(access_modes) or 'none'}; storage class {storage_class or NOT_SET}.",
        )
        if not storage_class:
            add("PVCStorageClassNotSet", "storageClassName is not set; the cluster default class applies, if any.")
        if "ReadWriteMany" in access_modes:
            add("PVCReadWriteMany", "Claim allows ReadWriteMany: several nodes can mount it read-write.")

    elif kind == "PodDisruptionBudget":
        minimum = spec.get("minAvailable")
        maximum = spec.get("maxUnavailable")
        add(
            "PDBConfigured",
            f"minAvailable={NOT_SET if minimum is None else minimum}; "
            f"maxUnavailable={NOT_SET if maximum is None else maximum}.",
        )
        if maximum in (100, "100%") or minimum in (0, "0%"):
            add("PDBAllowsAllDisruption", "The budget allows every pod to be disrupted at once.")

    elif (item.get("apiVersion", "") or "").startswith(CONFLUENT_API_PREFIX):
        _confluent_findings(item, add)
    elif kind == "ClusterRole":
        if not name.startswith("system:"):
            for audit, details in rbac_rule_risks(item.get("rules", [])).items():
                add("Cluster" + audit, f"ClusterRole grants {'; '.join(details)}.")

    elif kind == "ClusterRoleBinding" and not name.startswith("system:"):
        ref = item.get("roleRef", {}) or {}
        subjects = item.get("subjects", []) or []
        counts = Counter(subject.get("kind", "unknown") for subject in subjects)
        summary = ", ".join(f"{count} {subject_kind}" for subject_kind, count in sorted(counts.items())) or "none"
        add(
            "ClusterRoleBindingConfigured",
            f"Binds ClusterRole '{ref.get('name', '')}' to subjects: {summary}. Subject names are omitted.",
        )
        if ref.get("name") == "cluster-admin":
            add("ClusterBindingToClusterAdmin", "Binds cluster-admin, which grants every permission cluster-wide.")
        groups = sorted({s.get("name", "") for s in subjects if s.get("name") in BROAD_IDENTITIES})
        if groups:
            add("ClusterBindingToBroadGroup", f"Grants cluster-wide access to broad subject(s): {', '.join(groups)}.")

    elif kind in ("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
        for hook in item.get("webhooks", []) or []:
            hook_name = hook.get("name", "")
            policy = hook.get("failurePolicy", "Fail")  # the API server's default
            add("WebhookConfigured", f"Webhook {hook_name}: failurePolicy {policy}.")
            if policy == "Ignore":
                add(
                    "WebhookFailurePolicyIgnore",
                    f"Webhook {hook_name} ignores its own failures, so requests are admitted when it is unavailable.",
                )
            if (hook.get("clientConfig") or {}).get("url"):
                add(
                    "WebhookExternalURL",
                    f"Webhook {hook_name} calls an external URL rather than an in-cluster service.",
                )

    elif kind == "Node":
        version = ((item.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion", NOT_SET)
        add("NodeKubeletVersion", f"Kubelet {version}.")

    if kind in POD_TEMPLATE_KINDS or kind == "Pod":
        pod_spec = pod_spec_of(item)
        service_account = pod_spec.get("serviceAccountName", "default")
        if pod_spec.get("automountServiceAccountToken") is True and service_account != "default":
            add(
                "PodTokenAutomountExplicit",
                f"Sets automountServiceAccountToken: true for service account '{service_account}'. This overrides the "
                "account's own setting.",
            )

    return findings


def _confluent_findings(item: Dict[str, Any], add: Callable[[str, str], None]) -> None:
    """Declared configuration of Confluent Platform resources. Paths were confirmed with `oc explain` against the served
    CRDs (Kafka listeners, SchemaRegistry, ControlCenter, Connect, KafkaTopic, ConfluentRolebinding). Only whitelisted
    fields are read, so secret references and principal names never reach the report."""
    kind = (item.get("kind", "") or "").lower()
    spec = item.get("spec", {}) or {}

    if kind == "kafka":
        raw_listeners = spec.get("listeners")
        listeners: Dict[str, Any] = raw_listeners if isinstance(raw_listeners, dict) else {}
        # Built-in and custom listeners share the verified auth and TLS fields, so they are checked the same way
        entries: List[Tuple[str, Any]] = [
            (name, listeners.get(name)) for name in ("internal", "external", "replication")
        ]
        custom = listeners.get("custom")
        if isinstance(custom, list):
            entries += [(f"custom {c.get('name', NOT_SET)}", c) for c in custom if isinstance(c, dict)]
        described: List[str] = []
        no_auth: List[str] = []
        no_tls: List[str] = []
        for label, config in entries:
            if not isinstance(config, dict):
                continue  # not declared
            auth = (config.get("authentication") or {}).get("type")
            tls_enabled = (config.get("tls") or {}).get("enabled") is True
            port = f", port {config['port']}" if "port" in config else ""
            described.append(
                f"{label}{port}: auth {auth or NOT_SET}, tls {'enabled' if tls_enabled else 'not enabled'}"
            )
            if not auth:
                no_auth.append(label)
            if not tls_enabled:
                no_tls.append(label)
        add(
            "ConfluentKafkaListeners",
            f"{'; '.join(described) or 'no listeners declared'}. Declared configuration; runtime behaviour is not tested.",
        )
        if no_auth:
            add("ConfluentListenerAuthNotDeclared", f"No authentication type declared for: {', '.join(no_auth)}.")
        if no_tls:
            add("ConfluentListenerTLSNotDeclared", f"TLS not declared as enabled for: {', '.join(no_tls)}.")

    elif kind == "kafkatopic":
        replicas = spec.get("replicas")
        add(
            "ConfluentTopicConfigured",
            f"Partitions {spec.get('partitionCount', NOT_SET)}; replicas {replicas if replicas is not None else NOT_SET}.",
        )
        if replicas == 1:
            add(
                "ConfluentTopicReplicationOne",
                "Replication factor 1: data on the partition's broker is not replicated.",
            )

    elif kind == "confluentrolebinding":
        role = spec.get("role", NOT_SET)
        patterns = spec.get("resourcePatterns") or []
        principal_type = (spec.get("principal") or {}).get("type", NOT_SET)  # user | group; the name is omitted
        add(
            "ConfluentRoleBindingConfigured",
            f"Role {role}; principal type {principal_type}; {len(patterns)} resource pattern(s). Principal name omitted.",
        )
        if role in PRIVILEGED_CONFLUENT_ROLES:
            add("ConfluentPrivilegedRoleBinding", f"Grants the privileged role {role}.")

    elif kind in CONFLUENT_COMPONENTS:
        # Verified: spec.authentication.type (REST: basic | mtls | oauth) and spec.dependencies.kafka.authentication.type
        # (Kafka client). The tls block is verified to exist, but the schema for these kinds has no `enabled` flag, so
        # only the block's presence is reported
        rest_auth = (spec.get("authentication") or {}).get("type")
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else None
        has_tls_block = tls is not None
        kafka_client = kind in ("connect", "controlcenter")
        kafka_auth = (((spec.get("dependencies") or {}).get("kafka") or {}).get("authentication") or {}).get("type")

        tls_detail = (
            "tls block not declared"
            if tls is None
            else (
                f"tls block declared, secretRef {'set' if tls.get('secretRef') else 'not set'}, "
                f"autoGeneratedCerts {tls.get('autoGeneratedCerts', NOT_SET)} "
                "(the schema has no enabled flag, so whether TLS is active is not assessed)"
            )
        )
        parts = [f"REST authentication {rest_auth or NOT_SET}", tls_detail]
        if kafka_client:
            parts.append(f"Kafka client authentication {kafka_auth or NOT_SET}")
        add(
            "ConfluentComponentConfigured",
            f"{'; '.join(parts)}. Declared configuration; secret references are not read.",
        )
        if not rest_auth:
            add("ConfluentComponentAuthNotDeclared", "No REST authentication type declared.")
        if not has_tls_block:
            add("ConfluentComponentTLSNotDeclared", "No tls block declared.")
        if kafka_client and not kafka_auth:
            add(
                "ConfluentComponentKafkaAuthNotDeclared",
                "No Kafka client authentication declared under dependencies.kafka.",
            )


def _spec_view(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Security-relevant pod settings, keyed by path. Unset is kept distinct from an explicit false."""
    view: Dict[str, Any] = {
        "hostNetwork": spec.get("hostNetwork", NOT_SET),
        "hostPID": spec.get("hostPID", NOT_SET),
        "hostIPC": spec.get("hostIPC", NOT_SET),
        "automountServiceAccountToken": spec.get("automountServiceAccountToken", NOT_SET),
        # An empty securityContext is the API server's default, so unset and {} are the same here
        "securityContext": spec.get("securityContext") or {},
    }
    for container in (spec.get("initContainers") or []) + (spec.get("containers") or []):
        view[f"{container.get('name', '?')}.securityContext"] = container.get("securityContext") or {}
    return view


def spec_differences(template_spec: Dict[str, Any], pod_spec: Dict[str, Any]) -> List[str]:
    """Names of the security-relevant settings that differ between a template and a Pod. Values are not reported"""
    template, pod = _spec_view(template_spec), _spec_view(pod_spec)
    return sorted(key for key in set(template) | set(pod) if template.get(key, NOT_SET) != pod.get(key, NOT_SET))


def cross_object_findings(
    items: List[Dict[str, Any]],
    scoped_namespaces: Iterable[str],
    is_collected: Callable[[str, str], bool],
) -> List[Dict[str, Any]]:
    """Checks that need more than one object.

    is_collected(namespace, resource) must be True only when that resource was actually listed for the namespace, so
    an absent object is reported only when its absence is known rather than a forbidden or failed request.
    """
    findings: List[Dict[str, Any]] = []
    role_risks: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
    templates: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    replicaset_owner: Dict[Tuple[str, str], str] = {}
    present: Set[Tuple[str, str]] = set()
    replicated: Counter = Counter()
    namespaces = set(scoped_namespaces)

    cluster_role_risks: Dict[str, Dict[str, List[str]]] = {}
    node_versions: Dict[str, str] = {}
    for item in items:
        kind = item.get("kind", "")
        metadata = item.get("metadata", {}) or {}
        namespace = metadata.get("namespace", "")
        name = metadata.get("name", "")
        if namespace:
            namespaces.add(namespace)
        if kind == "Role":
            risks = rbac_rule_risks(item.get("rules", []))
            if risks:
                role_risks[(namespace, name)] = risks
        if kind == "ClusterRole" and not name.startswith("system:"):
            cluster_risks = rbac_rule_risks(item.get("rules", []))
            if cluster_risks:
                cluster_role_risks[name] = cluster_risks
        if kind == "Node":
            node_versions[name] = ((item.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion", NOT_SET)
        if kind in POD_TEMPLATE_KINDS - {"ReplicaSet"}:
            templates[(namespace, kind, name)] = pod_spec_of(item)
        if kind == "ReplicaSet":
            owner = _controller_owner(metadata)
            if owner and owner[0] == "Deployment":
                replicaset_owner[(namespace, name)] = owner[1]
        if kind in ("ResourceQuota", "LimitRange", "PodDisruptionBudget"):
            present.add((namespace, kind))
        if kind in REPLICATED_KINDS and (item.get("spec", {}) or {}).get("replicas", 1) > 1:
            replicated[namespace] += 1

    for item in items:
        if item.get("kind") != "RoleBinding":
            continue
        metadata = item.get("metadata", {}) or {}
        ref = item.get("roleRef", {}) or {}
        matched = role_risks.get((metadata.get("namespace", ""), ref.get("name", "")))
        if ref.get("kind") == "Role" and matched:
            findings.append(
                _make(
                    "BindingToRiskyRole",
                    f"Binds Role '{ref.get('name', '')}', which grants: "
                    + "; ".join(f"{audit} ({', '.join(details)})" for audit, details in sorted((matched or {}).items()))
                    + ".",
                    metadata.get("namespace", ""),
                    "RoleBinding",
                    metadata.get("name", ""),
                )
            )

    for item in items:
        if item.get("kind") != "ClusterRoleBinding" or item.get("metadata", {}).get("name", "").startswith("system:"):
            continue
        ref = item.get("roleRef", {}) or {}
        matched = cluster_role_risks.get(ref.get("name", ""))
        if ref.get("kind") == "ClusterRole" and matched:
            findings.append(
                _make(
                    "ClusterBindingToRiskyRole",
                    f"Binds ClusterRole '{ref.get('name', '')}', which grants: "
                    + "; ".join(f"{audit} ({', '.join(details)})" for audit, details in sorted((matched or {}).items()))
                    + ".",
                    "",
                    "ClusterRoleBinding",
                    item.get("metadata", {}).get("name", ""),
                )
            )

    # Nodes on different kubelet minor versions: one finding per node when the set of minors is not a single value
    minors = {node: ".".join(version.lstrip("v").split(".")[:2]) for node, version in node_versions.items()}
    if len(set(minors.values()) - {"not set"}) > 1:
        for node, version in sorted(node_versions.items()):
            others = sorted(set(minors.values()) - {minors[node]})
            findings.append(
                _make(
                    "NodeKubeletVersionSkew",
                    f"Kubelet {version} differs from other nodes (minor versions {', '.join(others)}).",
                    "",
                    "Node",
                    node,
                )
            )
    for item in items:
        if item.get("kind") != "Pod":
            continue
        metadata = item.get("metadata", {}) or {}
        namespace = metadata.get("namespace", "")
        owner = _controller_owner(metadata)
        if not owner:
            continue
        owner_kind, owner_name = owner
        if owner_kind == "ReplicaSet":
            owner_kind = "Deployment"
            owner_name = replicaset_owner.get((namespace, owner_name), "")
        template = templates.get((namespace, owner_kind, owner_name)) if owner_name else None
        if template is None:
            continue
        differences = spec_differences(template, pod_spec_of(item))
        if differences:
            findings.append(
                _make(
                    "PodDiffersFromTemplate",
                    f"Differs from its {owner_kind} template in: {', '.join(differences)}. The template may have changed "
                    "since this Pod was created, and admission can mutate Pods.",
                    namespace,
                    "Pod",
                    metadata.get("name", ""),
                )
            )

    for namespace in sorted(namespaces):
        checks = [
            ("ResourceQuota", "resourcequotas", "NamespaceWithoutResourceQuota", "No ResourceQuota in this namespace."),
            ("LimitRange", "limitranges", "NamespaceWithoutLimitRange", "No LimitRange in this namespace."),
        ]
        for kind, resource, audit, msg in checks:
            if (namespace, kind) not in present and is_collected(namespace, resource):
                findings.append(_make(audit, msg, namespace, "Namespace", namespace))
        if (
            replicated[namespace]
            and (namespace, "PodDisruptionBudget") not in present
            and is_collected(namespace, "poddisruptionbudgets")
        ):
            findings.append(
                _make(
                    "NamespaceWithoutPDB",
                    f"{replicated[namespace]} Deployment/StatefulSet with replicas > 1 and no PodDisruptionBudget here. A "
                    "budget may still select these pods; check its selector.",
                    namespace,
                    "Namespace",
                    namespace,
                )
            )

    return findings
