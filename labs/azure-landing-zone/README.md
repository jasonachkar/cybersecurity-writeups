# Azure landing-zone hierarchy and policy lab

This lab compiles a small tenant-scope Bicep design for a management-group hierarchy and an audit-first custom policy assignment. It demonstrates deployment shape, federated CI identity, and a reviewable what-if boundary; it does not deploy during repository validation.

## Architecture decision

The sample separates platform, landing-zone, and sandbox subscriptions beneath an organization root. The policy begins with `audit`, because changing a broad management-group policy to `deny` before impact analysis can interrupt workloads. Production design still needs connectivity, identity, security, decommissioned, and workload-archetype management groups based on the organization's operating model.

## Prerequisites and compile

- Azure CLI 2.83.0 or later with Bicep support.
- No Azure login is needed to compile.

<div class="language-powershell highlight">

<span id="__span-0-1"><span class="n">`az`</span>` `<span class="n">`bicep`</span>` `<span class="n">`build`</span>` `<span class="p">`-`</span><span class="o">`-file`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`azure-landing-zone`</span><span class="p">`/`</span><span class="n">`main`</span><span class="p">`.`</span><span class="n">`bicep`</span>` `</span>

</div>

Expected result: Bicep returns a compiled ARM template without diagnostics. The repository code validator performs this compilation when Azure CLI is available and reports an explicit limitation otherwise.

## What-if, not deployment

After replacing every angle-bracket placeholder, an authorized reviewer may inspect:

<div class="language-powershell highlight">

<span id="__span-1-1"><span class="n">`az`</span>` `<span class="n">`login`</span>` `<span class="p">`-`</span><span class="n">`-tenant`</span>` `<span class="p">`<`</span><span class="n">`tenant-id`</span><span class="p">`>`</span>` `<span class="p">`-`</span><span class="n">`-allow-no-subscriptions`</span>` `</span><span id="__span-1-2"><span class="n">`az`</span>` `<span class="n">`deployment`</span>` `<span class="n">`tenant`</span>` `<span class="n">`what-if`</span>` `<span class="p">`` ` ``</span>` `</span><span id="__span-1-3">` `<span class="p">`-`</span><span class="n">`-name`</span>` `<span class="n">`landing-zone-review`</span>` `<span class="p">`` ` ``</span>` `</span><span id="__span-1-4">` `<span class="p">`-`</span><span class="n">`-location`</span>` `<span class="n">`canadacentral`</span>` `<span class="p">`` ` ``</span>` `</span><span id="__span-1-5">` `<span class="p">`-`</span><span class="n">`-template`</span><span class="o">`-file`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`azure-landing-zone`</span><span class="p">`/`</span><span class="n">`main`</span><span class="p">`.`</span><span class="n">`bicep`</span>` `<span class="p">`` ` ``</span>` `</span><span id="__span-1-6">` `<span class="p">`-`</span><span class="n">`-parameters`</span>` `<span class="s1">`'@labs/azure-landing-zone/parameters.example.json'`</span>` `</span>

</div>

The included workflow uses GitHub OIDC and a protected environment. Configure the federated credential with an exact repository/environment subject, constrain the service principal to the required tenant/management-group operations, and require a human review of the what-if artifact. Do not add a client secret.

## Deployment and rollback considerations

Management-group and policy changes have a wide blast radius. Roll out new policy in audit mode, inventory noncompliance, assign named exemption owners with expiry, pilot a narrow management group, then move to deny only with tested break-glass and rollback procedures. Removing a policy assignment does not undo resource mutations performed by `deployIfNotExists` or `modify`; this sample deliberately uses `audit`.

## Negative cases to review

- placeholder or duplicate management-group IDs;
- an OIDC subject broader than the protected environment;
- policy enforcement before exemptions and regional dependencies are inventoried;
- a hierarchy move that changes inherited role and policy scope;
- subscription vending without ownership, budget, network, logging, and lifecycle metadata;
- a tenant-level deployment identity with permanent credentials or excessive roles.

## Cleanup and limitations

Compilation creates `main.json`; remove that generated file after inspection. This lab does not execute what-if in CI because it has no authorized tenant, and it does not deploy, move subscriptions, create role assignments, configure networking, or validate tenant-specific Azure Policy aliases. What-if itself is predictive output, not proof of runtime correctness.

## References

- [Azure landing zones](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/)
- [Landing-zone design areas](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-areas)
- [Management-group design guidance](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/resource-org-management-groups)
- [Subscription vending guidance](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/subscription-vending)
- [Use GitHub OIDC to access Azure](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect)
