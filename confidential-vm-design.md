# Design note: `--vm --confidential` (SEV-SNP / TDX)

**Status:** deferred — design only, not implemented.
**Date:** 2026-06-11.

This note records the intended shape of a confidential-VM mode so it can be
picked up later. It is deliberately *not* shipped as a flag yet: a half-feature
that turns on a CPU mode without an attestation story gives the appearance of
confidentiality without the guarantee, which is worse than nothing.

## Goal

Run an oci2bin binary's payload inside a hardware-encrypted, attestable VM so
that **the host operator cannot read or tamper with the guest's memory**.
Pitch: "scp one binary to an untrusted host and run it in an enclave."

This extends the existing `--vm` mode (`run_as_vm_ch`, cloud-hypervisor /
`run_as_vm_libkrun`), it does not replace the container path.

## What the hardware provides

| Tech | Vendor | Protects | Attestation |
|------|--------|----------|-------------|
| SEV-SNP | AMD | Guest RAM encrypted + integrity (anti-remap) | Report signed by AMD PSP, verified against AMD VCEK/ARK |
| TDX | Intel | Guest RAM encrypted + integrity (TD) | TD Quote signed via Intel SGX QE, verified against Intel PCS |

Both give **encryption-in-use** + a **measured launch**: a quote attesting to
the initial guest memory/firmware measurement, which a relying party verifies
before releasing secrets to the guest.

## Why a thin flag is not enough

Turning on `sev_snp=on` gets you memory encryption but **none of the value**
without the rest of the chain:

1. **Measured boot** — the kernel/initramfs/cmdline must be measured into the
   launch digest. oci2bin embeds the kernel + an initramfs built from the
   rootfs; those bytes must feed the measurement deterministically (pairs with
   `--reproducible`).
2. **Attestation** — the guest must fetch its SEV-SNP report / TD quote and a
   relying party must verify it against AMD/Intel roots **and** check that the
   measurement equals the expected value for *this* binary.
3. **Secret release** — only after a good quote should the workload's secrets
   be unsealed (ties into `--encrypt`'s age identity and the TPM2 secret path).

Without (2)+(3) you have encrypted RAM that nobody checks — no actual trust
gain. That is the trap this note exists to avoid.

## Proposed surface (when implemented)

```
oci2bin --vm --confidential[=sev-snp|tdx] <image> <out>
  # build: force --reproducible, record the expected launch measurement
  #        into OCI2BIN_META (so a verifier knows the good value)

OCI2BIN_ATTEST=strict ./out
  # run: probe host CEC, boot CVM, fetch quote, verify vs embedded
  #      measurement + vendor roots, release secrets only on success
```

- `--confidential` with no value auto-detects the platform.
- Build forces reproducible mode; non-reproducible input is rejected (the
  measurement would not be stable).

## Implementation sketch

1. **Host capability probe** (cheap, ship-able on its own):
   - SEV-SNP: `/dev/sev` present, `/sys/module/kvm_amd/parameters/sev_snp == Y`.
   - TDX: `/sys/module/kvm_intel/parameters/tdx == Y`, `/dev/tdx_guest`.
   - Add to `oci2bin doctor`/`explain` so users learn if a host qualifies.
   - Fail clearly and early when `--confidential` is asked for on a host
     without the capability (do **not** silently fall back to a plain VM).
2. **VMM launch flags** (cloud-hypervisor):
   - SEV-SNP: `--platform sev_snp=on` plus the SNP/OVMF firmware blob; libkrun
     has its own confidential path and would be a separate backend.
3. **Measurement**: compute/record the expected launch digest at build into
   `OCI2BIN_META` (`confidential_measurement`), gated on `--reproducible`.
4. **Attestation agent in guest**: a tiny in-guest step fetches the report
   (`/dev/sev-guest` ioctl / `/dev/tdx_guest`) and either self-verifies against
   the embedded measurement or hands the quote to an external relying party.
5. **Secret release**: only unseal `--encrypt` / TPM2 secrets after a good
   quote — reuse `memfd_secret` for in-guest plaintext.

## Open questions

- Self-verification (embedded expected measurement) vs. an external relying
  party. Self-verification shares the embedded-anchor caveat documented for
  `--require-signed`; real assurance wants an external verifier holding the
  policy + secrets.
- VCEK/ARK (AMD) and PCS (Intel) cert fetching needs network or a cached cert
  bundle — conflicts with `--offline-only` unless certs are pre-embedded.
- libkrun vs cloud-hypervisor confidential support differ; pick one first
  (cloud-hypervisor SEV-SNP is the most documented).

## Recommendation

Land the **host-capability probe** in `doctor`/`explain` first (useful, low
risk, no false promises). Treat the full CVM + attestation + secret-release
chain as its own project, scoped against a specific host (a real SEV-SNP or
TDX machine) so the measurement and quote-verification paths can be tested
end to end rather than guessed.
