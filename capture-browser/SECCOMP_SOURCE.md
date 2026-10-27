# seccomp.json provenance

`seccomp.json` is Docker's CURRENT default profile plus exactly one added rule:

    {"names": ["chroot", "clone", "unshare"], "action": "SCMP_ACT_ALLOW"}   (unconditional)

That is all Chromium's namespace sandbox needs when the container drops every
capability: `clone` with CLONE_NEWUSER|CLONE_NEWPID (the zygote), `unshare`, and
`chroot` (the sandbox chroots into /proc/self/fdinfo). Docker's default gates all
three on CAP_SYS_ADMIN / CAP_SYS_CHROOT; adding those capabilities instead would
be wider, so the profile is relaxed and `cap_drop: [ALL]` stays. `clone3` is left
as in Docker's default (ENOSYS for non-privileged), so glibc falls back to `clone`.

- Base: `seccomp/default.json` in github.com/moby/profiles, commit
  `6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef` (2026-09-17).
- Reference consulted: Playwright's `utils/docker/seccomp_profile.json`
  (microsoft/playwright; last commit touching it `ae935a43d9e376e4759548f6b3c6905c7b282333`,
  2021-01-03). It was tried first and works, but only together with the
  SYS_CHROOT capability, it predates today's Docker default (lacks ~48 syscalls
  such as `clone3`, `close_range`, `openat2`, `faccessat2`), and it ALLOWS
  `io_uring_setup/enter/register`, which Docker's default deliberately denies.
  It was therefore not used as the base.
- To regenerate: fetch moby's default.json, append the rule above.
- Re-verify after a Playwright/Chromium bump: `scripts/capture_spike.sh` fails
  closed (the browser will not launch) if the sandbox cannot start.
