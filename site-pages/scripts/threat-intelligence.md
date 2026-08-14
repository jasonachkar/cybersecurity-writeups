# Threat Intelligence scripts

The threat intelligence scripts and packages I've written, with their source shown directly below — no need to open GitHub to read them.

<div id="cloudtrail-analyzer" class="section" aria-labelledby="cloudtrail-analyzer-heading">

## CloudTrail suspicious-activity analyzer

<span class="docs-badge">Go</span><span class="docs-badge">Read-only</span><span class="docs-badge">Go test suite (9 cases)</span>

### What it does

It turns a batch of exported AWS CloudTrail events into a short list of findings worth a human look: console logins without MFA, privilege-escalation chains within a time window, repeated KMS Decrypt denies, and signs of log tampering (StopLogging / DeleteTrail).

### Why I wrote it

Reading the incident case studies made it obvious how much of a real investigation is just pattern-spotting across thousands of events, so I wrote a small analyzer that does the first pass of that for CloudTrail.

### How it works

ParseEvents decodes a CloudTrail JSON export into typed events. Analyze runs four independent passes over that list — console-login, privilege-chain, KMS-deny-threshold, and log-tampering — each returning its own Finding records, which the caller merges.

### Requirements

- Go 1.22+
- A CloudTrail JSON export to analyze — it does not call AWS APIs itself.

### Permissions and safety

None from the tool itself. Reading the CloudTrail export is on you; treat that export as sensitive data regardless of what this analyzer does with it.

### Usage

    go test ./threat-intel/scripts/cloudtrail/...

### Inputs

Raw CloudTrail JSON bytes (a \[\]byte), plus an Options struct for thresholds like the privilege-chain time window and KMS-deny count.

### Outputs

A \[\]Finding slice: which analysis flagged it, the actor ARN, and a description.

### What I tested

analyze_test.go covers each of the four analyses with both events that should fire a finding and quiet events that should not.

### Limitations

- This flags patterns worth checking, not confirmed compromise — every finding needs a human to correlate it against what was actually authorized.
- It only understands the CloudTrail event shape it was built against; it has not been run against a live account's trail.
- No CLI entry point yet; exercised via Analyze()/ParseEvents() and its test suite.

### Related research

- Related research: [Incident case studies](/threat-intel/cloud-breach-case-studies/)

</div>
