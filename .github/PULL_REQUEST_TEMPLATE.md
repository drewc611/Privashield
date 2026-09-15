## Summary

Describe what this change does and why it is needed.

## Change type

- [ ] Feature
- [ ] Bug fix
- [ ] Security fix
- [ ] Refactor
- [ ] Documentation
- [ ] Dependency/build change

## Security and privacy impact

- [ ] No material security/privacy impact
- [ ] Changes a trust boundary
- [ ] Handles sensitive data
- [ ] Changes authentication/authorization
- [ ] Changes AI/model behavior
- [ ] Changes policy or enforcement behavior
- [ ] Adds or changes a privileged capability

Explain any checked security/privacy item:

## Testing

Describe tests run and relevant results.

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Negative/security tests added where applicable
- [ ] Failure/rollback behavior tested where applicable

## Documentation

- [ ] Documentation is unchanged because external behavior did not change
- [ ] Documentation updated
- [ ] ADR added/updated for a consequential architecture decision

## Operational impact

Document migrations, new ports, permissions/capabilities, configuration, dependencies, resource requirements, or rollback constraints.

## Checklist

- [ ] No secrets or sensitive production/customer data are included
- [ ] Inputs are validated and attacker-controlled content is treated as untrusted
- [ ] Model output does not directly gain privileged authority
- [ ] Relevant logs/metrics are present without leaking sensitive values
- [ ] I have reviewed `SECURITY.md` and `CONTRIBUTING.md`
