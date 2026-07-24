/**
 * Pinned third-party tool and CRD versions for offline/CI verification.
 *
 * Binary SHA256 digests were taken from the upstream release checksum files
 * (OPA *.sha256, Gitleaks checksums.txt, Kyverno checksums.txt) on 2026-07-24.
 * CRD digests are SHA-256 of the exact raw GitHub contents at the tagged refs.
 *
 * If a platform asset is unused by current CI, its sha256 may be omitted from
 * selection logic, but values below are the published digests for that asset.
 */

export const OPA_VERSION = "1.17.0";
export const KYVERNO_CLI_VERSION = "1.18.2";
export const GITLEAKS_VERSION = "8.30.0";
export const TETRAGON_CRD_VERSION = "1.7.0";
export const KYVERNO_IVP_CRD_VERSION = "1.18.2";
export const TERRAFORM_VERSION = "1.14.6";
export const PLAYWRIGHT_VERSION = "1.61.1";
export const AXE_CORE_VERSION = "4.12.1";
export const HTML_VALIDATE_VERSION = "11.5.6";
export const SHELLCHECK_VERSION = "0.10.0";
export const BICEP_VERSION = "0.36.1";
export const POWERSHELL_VERSION = "7.4.6";

export const SHELLCHECK_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz`,
    sha256: "6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87"
  }
};

export const BICEP_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/Azure/bicep/releases/download/v${BICEP_VERSION}/bicep-linux-x64`,
    sha256: "db96c7082e0f964eb5a743dd67683c9325352e85ec209daeab955b6851014dd8"
  }
};

export const POWERSHELL_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz`,
    sha256: "6f6015203c47806c5cc444c19d8ed019695e610fbd948154264bf9ca8e157561"
  }
};

export const OPA_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64`,
    sha256: "5485f9c32548af84bc0bfa06a7f40a98ecc742477a7f9f24ea3556d221dc295f"
  },
  "linux-amd64-static": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static`,
    sha256: "e83da46804832578e9d9e1733dffbe4d3b5f8cc9c26eb124da9ceea4abfe189f"
  },
  "linux-arm64": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_arm64`,
    sha256: "02da9afdf1433b067ccc1271b40669296bcaadc37ae43fab0285892a4ddb2eed"
  },
  "darwin-amd64": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_darwin_amd64`,
    sha256: "088f6c9d8c7b0e2ee0bee450cba7599953e3167649f3623019bada67a26229a4"
  },
  "darwin-arm64": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_darwin_arm64`,
    sha256: "48360aaa595e5bb2ae412355519f99e57360413552bb2b8786e9968a227fa009"
  },
  "windows-amd64": {
    url: `https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_windows_amd64.exe`,
    sha256: "d319e1abca6b1683e79e4e3ddb840b098c45a9257426ba998917dac8d83b7574"
  }
};

export const GITLEAKS_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
    sha256: "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e"
  },
  "linux-arm64": {
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`,
    sha256: "b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f"
  },
  "darwin-amd64": {
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`,
    sha256: "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5"
  },
  "darwin-arm64": {
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
    sha256: "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7"
  },
  "windows-amd64": {
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`,
    sha256: "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"
  }
};

export const KYVERNO_CLI_ARTIFACTS = {
  "linux-amd64": {
    url: `https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}/kyverno-cli_v${KYVERNO_CLI_VERSION}_linux_x86_64.tar.gz`,
    sha256: "cb2feb8356149fd2fe774c894ccf0969f4a60a83867dd913af724f74ffbbc18b"
  },
  "darwin-amd64": {
    url: `https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}/kyverno-cli_v${KYVERNO_CLI_VERSION}_darwin_x86_64.tar.gz`,
    sha256: "a461096a3111e6a4134c2bd135ddd8e0bfd9d466a5d5b17810b76a484fffdae4"
  },
  "darwin-arm64": {
    url: `https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}/kyverno-cli_v${KYVERNO_CLI_VERSION}_darwin_arm64.tar.gz`,
    sha256: "cc69bc6638da1993146c134943fac91cbc9dd0ce60a3e88c6d7c518ae00f1abc"
  },
  "windows-amd64": {
    url: `https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}/kyverno-cli_v${KYVERNO_CLI_VERSION}_windows_x86_64.zip`,
    sha256: "b5c9d1cb75587a312dc8334537a5773bdedb1a985deae9d89a5251385afb831f"
  }
};

/** Tetragon TracingPolicyNamespaced CRD at tagged v1.7.0. */
export const TETRAGON_CRD = {
  version: TETRAGON_CRD_VERSION,
  url: "https://raw.githubusercontent.com/cilium/tetragon/v1.7.0/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml",
  sha256: "173a439c9932509e27daa4d0dbe96433299a123f82ba7d3dcdf6a3c8d46b3f14",
  policyPath: "appsec/runtime-protection-rasp-waf/tetragon-v1.7.0-shell-policy.yaml"
};

/** Kyverno ImageValidatingPolicy CRD at tagged v1.18.2. */
export const KYVERNO_IVP_CRD = {
  version: KYVERNO_IVP_CRD_VERSION,
  url: "https://raw.githubusercontent.com/kyverno/kyverno/v1.18.2/config/crds/policies.kyverno.io/policies.kyverno.io_imagevalidatingpolicies.yaml",
  sha256: "3528151f3717c9946ee56d60866f2cf6c29a4b1a7e759c72af60451147b995c2",
  policyPath: "labs/kubernetes-security/policies/verify-release-images.yaml"
};

export const TOOL_PINS = {
  opa: {version: OPA_VERSION, artifacts: OPA_ARTIFACTS},
  gitleaks: {version: GITLEAKS_VERSION, artifacts: GITLEAKS_ARTIFACTS},
  kyvernoCli: {version: KYVERNO_CLI_VERSION, artifacts: KYVERNO_CLI_ARTIFACTS},
  tetragonCrd: TETRAGON_CRD,
  kyvernoIvpCrd: KYVERNO_IVP_CRD,
  terraform: {version: TERRAFORM_VERSION},
  playwright: {version: PLAYWRIGHT_VERSION},
  axeCore: {version: AXE_CORE_VERSION},
  htmlValidate: {version: HTML_VALIDATE_VERSION},
  shellcheck: {version: SHELLCHECK_VERSION, artifacts: SHELLCHECK_ARTIFACTS},
  bicep: {version: BICEP_VERSION, artifacts: BICEP_ARTIFACTS},
  powershell: {version: POWERSHELL_VERSION, artifacts: POWERSHELL_ARTIFACTS}
};
