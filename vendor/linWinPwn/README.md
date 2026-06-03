# linWinPwn (vendored)

`linWinPwn.sh` is **not part of cedzo** — it is a third-party Active Directory
enumeration & attack framework, vendored here for reference and optional manual
use.

- **Upstream:** https://github.com/lefayjey/linWinPwn
- **Author:** lefayjey
- **License:** see upstream repository (retain the original author's notice).

## Why it's here

cedzo is **recon-only by design** — no password spraying, no credential brute
force, no exploitation. linWinPwn, by contrast, is a full offensive toolkit:
its `--auto` mode performs RID/kerbrute brute forcing, password spraying,
Kerberos roasting *attacks*, coercion checks, and credential dumping
(secretsdump), in addition to enumeration.

To respect cedzo's recon-only guarantee, we did **not** wire linWinPwn's
attack paths into the pipeline. Instead, cedzo's phase `06-ad-recon.sh`
natively re-implements only linWinPwn's **read-only enumeration** techniques
that cedzo previously lacked:

| cedzo 06 sub-task | linWinPwn equivalent | Read-only? |
|-------------------|----------------------|------------|
| `ldap_recon` | `ne_ldap_enum` (dc-list, password-not-required, MAQ, subnets, get-desc-users, get-userPassword) | ✅ directory queries |
| `delegation` | `deleg_enum` (netexec find/trusted-for-delegation + impacket findDelegation) | ✅ directory queries |
| `sccm` | `ne_sccm` (netexec `-M sccm`) | ✅ discovery |
| `timeroast` | `ne_timeroast` (netexec `-M timeroast`) | ✅ collection for OFFLINE cracking |
| `ldeep` | `ldeep_enum` (full LDAP dump) | ✅ directory dump |

Everything destructive or spray/brute-based in linWinPwn (`bruteforce`,
`kerberos` *attacks*, `pwd_dump`, coercion, `passpray`, `pre2k` auth) was
deliberately **left out** of the cedzo integration.

## Running the full framework manually

If you have explicit authorisation for active exploitation that goes beyond
cedzo's recon scope, you can run the vendored tool directly — it is entirely
self-contained and independent of cedzo:

```bash
./vendor/linWinPwn/linWinPwn.sh -t <dc_ip> -d <domain> -u <user> -p <password>
# or, automatic enumeration (NOTE: includes brute-force/spray/attacks):
./vendor/linWinPwn/linWinPwn.sh -t <dc_ip> -d <domain> -u <user> -p <password> --auto
```

This is outside cedzo's recon-only remit; use it only within your rules of
engagement.
