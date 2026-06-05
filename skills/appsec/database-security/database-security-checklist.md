# Database Security Checklist

Use this checklist with `database-security/SKILL.md`. Mark each row `Pass`, `Fail`, `Not Applicable`, or `Not Evaluable`. A control is `Not Evaluable` when the reviewer lacks effective configuration, SQL metadata, network, audit, backup, or control-plane evidence.

---

## 1. Inventory and Scope

| ID | Check | Evidence | Fail Signal |
|---|---|---|---|
| DB-INV-01 | Database engine, version, environment, owner, and deployment model are recorded | Inventory, CMDB, IaC, managed-service export | Unknown engine/version/owner for in-scope database |
| DB-INV-02 | Data sensitivity is classified | Data inventory, schema classification, compliance scope | Sensitive or regulated data not identified |
| DB-INV-03 | Evidence sources and gaps are documented | Review notes | Reviewer cannot distinguish missing evidence from passing controls |
| DB-INV-04 | Managed-service inherited controls are identified separately from customer-managed controls | Cloud control-plane export, provider docs | Provider responsibility assumed without evidence |

---

## 2. Network Exposure

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-NET-01 | All | Production database is not publicly reachable unless explicitly justified | Endpoint state, firewall/security group rules, reachability evidence | Public endpoint with sensitive data and no approved need | Move behind private endpoint/VPC/VNet, restrict source networks |
| DB-NET-02 | PostgreSQL | `listen_addresses` matches expected private interfaces | `postgresql.conf`, managed parameter export | `listen_addresses = '*'` plus broad allow rules | Bind only expected interfaces or enforce private network controls |
| DB-NET-03 | PostgreSQL | `pg_hba.conf` CIDRs are narrow and ordered safely | `pg_hba.conf` | Broad `0.0.0.0/0` or `::/0` before narrow rules | Put narrow rules first, remove broad rules, document exceptions |
| DB-NET-04 | MySQL/MariaDB | Server bind address and network ACLs limit client reachability | `my.cnf`, cloud/network export | Bind all interfaces with broad inbound database port | Bind private interface and restrict network sources |
| DB-NET-05 | SQL Server | Enabled protocols and ports are limited to expected networks | SQL Server configuration, firewall export | Admin/database port reachable from broad non-admin networks | Restrict firewall, require private access path |

---

## 3. Authentication and Host Authorization

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-AUTH-01 | PostgreSQL | `trust` auth is absent outside tightly controlled local maintenance paths | `pg_hba.conf` | `trust` used for remote or broad client ranges | Replace with strong password, certificate, or federated auth where supported |
| DB-AUTH-02 | PostgreSQL | Sensitive TCP clients use `hostssl` where TLS is required | `pg_hba.conf`, TLS policy | `host` or `hostnossl` allows sensitive access | Use `hostssl` and verify certificate requirements where mandated |
| DB-AUTH-03 | PostgreSQL | Password auth method meets environment standard | `pg_hba.conf`, engine version | Legacy weak auth retained where stronger method is expected | Move to stronger supported auth and rotate affected credentials |
| DB-AUTH-04 | MySQL/MariaDB | Account host scope is narrow | User table export, account listing | `'app'@'%'` or omitted host for sensitive account | Scope accounts to expected hostnames, IP ranges, or private networks |
| DB-AUTH-05 | MySQL/MariaDB | Anonymous, shared, or orphaned accounts are absent | Account listing | Anonymous users, shared accounts, unknown owners | Remove or disable accounts, assign owners, enforce named access |
| DB-AUTH-06 | SQL Server | `sa` and SQL logins are controlled and justified | Login inventory, policy export | Enabled high-risk login with unknown owner or weak governance | Disable or rename where appropriate, enforce strong auth and ownership |
| DB-AUTH-07 | SQL Server | Fixed server role membership is limited and owned | `sys.server_role_members`, login inventory | App/support login in `sysadmin` without need | Remove from fixed admin roles, grant scoped permissions |

---

## 4. Transport Encryption

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-TLS-01 | PostgreSQL | SSL is enabled and enforced for sensitive clients | `postgresql.conf`, `pg_hba.conf`, cert evidence | `ssl = off` or no `hostssl` path | Enable SSL, enforce `hostssl`, validate certificate chain |
| DB-TLS-02 | MySQL/MariaDB | `require_secure_transport` or equivalent policy is enabled where required | Variable export, managed setting | Sensitive clients can connect without encryption | Enable secure transport and require SSL attributes for sensitive users |
| DB-TLS-03 | SQL Server | TLS certificate and encryption settings meet policy | Certificate evidence, SQL Server config | Missing certificate or unclear encryption enforcement | Install valid certificate, force encryption where required |
| DB-TLS-04 | All | Client certificate or mutual TLS requirement is evidenced where mandated | Auth/TLS policy, connection rules | mTLS requirement claimed but not configured | Add certificate requirements and document client enrollment |

---

## 5. Privilege Model

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-PRIV-01 | PostgreSQL | Application roles are not superusers and do not own broad schemas unnecessarily | Role attributes, grants, schema owners | Runtime role has `SUPERUSER`, broad ownership, or unrestricted DDL | Split owner/migration/runtime roles, revoke superuser |
| DB-PRIV-02 | PostgreSQL | Default privileges and grant option do not broaden future access unexpectedly | `ALTER DEFAULT PRIVILEGES`, grants | Future tables/routines grant broad write/admin access | Restrict default privileges and grant option |
| DB-PRIV-03 | MySQL/MariaDB | Application users lack global administrative privileges | Grants export | `ALL PRIVILEGES ON *.*`, `GRANT OPTION`, FILE, SUPER-like rights | Grant database/schema-specific privileges only |
| DB-PRIV-04 | SQL Server | Runtime logins are not fixed server admins | Role membership export | Runtime login in `sysadmin`, `securityadmin`, or equivalent | Remove fixed role, grant scoped database roles |
| DB-PRIV-05 | All | Runtime, migration, read-only, support, and DBA duties are separated | Role model, grants | One account handles app runtime and migrations/admin | Create separate accounts and rotate credentials |
| DB-PRIV-06 | All | Reporting/read-only users cannot modify data or execute privileged routines | Grants, routine permissions | Read-only account has write or execute-on-admin routine | Revoke write/execute permissions, create narrow reporting role |

---

## 6. Dangerous Engine Features

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-FEAT-01 | SQL Server | `xp_cmdshell` is disabled unless tightly justified | `sp_configure` export | `xp_cmdshell` enabled without approval and audit | Disable; if required, restrict, approve, and audit every use |
| DB-FEAT-02 | SQL Server | External scripts, unsafe CLR, linked servers, and cross-database chaining are controlled | Config export, linked server list | Unsafe execution or trust path enabled broadly | Disable or scope features, log and approve changes |
| DB-FEAT-03 | MySQL/MariaDB | `local_infile` and FILE privilege are restricted | Variable export, grants | `local_infile` enabled plus broad FILE privilege | Disable or restrict, monitor file access paths |
| DB-FEAT-04 | PostgreSQL | Untrusted languages, risky extensions, and `COPY PROGRAM` paths are controlled | Extension/language list, role attributes | Broad users can create/use risky extension or untrusted code | Restrict extension ownership and superuser-only capabilities |
| DB-FEAT-05 | All | Dangerous feature enablement is logged and reviewed | Audit settings, change tickets | Feature can be enabled without audit trail | Add change approval and privileged action logging |

---

## 7. Audit Logging and Telemetry

| ID | Engine | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|---|
| DB-AUDIT-01 | PostgreSQL | Security-relevant events are logged and forwarded | Logging settings, managed audit export, SIEM evidence | Failed logins, grants, DDL, or admin actions missing | Enable relevant logging or `pgaudit` where appropriate, forward logs |
| DB-AUDIT-02 | MySQL/MariaDB | Audit plugin or managed-service audit evidence exists for privileged actions | Audit settings, plugin state, log export | No evidence of admin/grant/activity logging | Enable audit plugin or managed audit features |
| DB-AUDIT-03 | SQL Server | SQL Server Audit records privileged actions and has a review path | Audit config, audit logs | Audit disabled or not reviewing security events | Configure SQL Server Audit and alert/review workflow |
| DB-AUDIT-04 | All | Audit logs include actor, client, object, action, outcome, and timestamp | Log samples | Logs cannot support incident reconstruction | Increase log detail and preserve required fields |
| DB-AUDIT-05 | All | Logs are retained and tamper-resistant for the required window | Retention policy, storage config | Logs only local to database host or short retention | Forward to SIEM/immutable storage with required retention |

---

## 8. Backup, Restore, and Recovery

| ID | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|
| DB-BACKUP-01 | Production backups are enabled and retained to meet recovery objectives | Backup policy, managed backup settings | Backups disabled or retention below RPO/RTO need | Enable backups and align retention to recovery requirements |
| DB-BACKUP-02 | Backups and exports are encrypted | Backup settings, KMS/key evidence | Unencrypted backup or unknown key owner | Enable backup encryption and document key ownership |
| DB-BACKUP-03 | Backup access is restricted | IAM/ACL/storage export | Broad access to dumps, snapshots, exports, or backup buckets | Restrict access and monitor reads/deletes |
| DB-BACKUP-04 | Restore or point-in-time recovery evidence exists | Restore drill, PITR validation | No recent restore evidence | Run and document restore test |
| DB-BACKUP-05 | Critical backup deletion is protected | Retention lock, deletion protection, cross-account/cross-region controls | Single writable backup path vulnerable to destructive admin | Add immutable retention or separated recovery copy |

---

## 9. Data Protection and Tenant Isolation

| ID | Check | Evidence | Fail Signal | Remediation Direction |
|---|---|---|---|---|
| DB-DATA-01 | Encryption at rest is enabled and key ownership is documented | Managed setting, KMS/key export | Sensitive database unencrypted or key owner unknown | Enable encryption and define key ownership/review |
| DB-DATA-02 | Key rotation and access review are evidenced | KMS policy, rotation setting, access review | Key never reviewed or broad key admin access | Enable rotation where supported and review key access |
| DB-DATA-03 | Multi-tenant isolation is enforced | RLS policy, schema model, tenant grants, app/database controls | Tenant filter only in application code with no database evidence | Add RLS/schema/role isolation or document compensating controls |
| DB-DATA-04 | Sensitive data classification and masking are implemented where required | Data classification, masking/tokenization evidence | Regulated data present without classification or masking plan | Classify data and apply masking/tokenization controls |
| DB-DATA-05 | Replicas, exports, and analytics copies have equivalent controls | Replica/export inventory | Downstream copy has weaker auth, TLS, encryption, or audit | Apply source-equivalent controls and include copies in inventory |

---

## Not Evaluable Guidance

Use `Not Evaluable` when:

- Only policy statements are provided without effective database metadata or configuration.
- Network posture is described but no endpoint, firewall, or security group evidence is available.
- TLS is claimed but no enforcement setting, host/client rule, or certificate evidence is available.
- Grants are described but no role/login/grant export is available.
- Audit logging is claimed but no audit configuration or sample event path is available.
- Backups are claimed but no backup policy, retention, access, encryption, or restore evidence is available.
- Managed-service controls are assumed without provider setting exports or documented responsibility mapping.
