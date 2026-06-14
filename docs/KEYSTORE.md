# Cloud-KMS keystore (`[keystore]`)

zecd can wrap a wallet's at-rest encryption key with a key held in **AWS KMS** or
**Google Cloud KMS** - the same "auto-unseal" pattern used by Vault, SOPS, and sealed
secrets, so it should feel routine to SRE/ops teams. This document covers how it works,
how to set it up on each cloud, what it protects against, and how to test it.

> **Build flag:** keystore support is the `keystore` cargo feature, **on by default** (so
> release binaries and Docker images include it). Users who don't want the cloud SDKs in
> their dependency tree can build with `cargo build --no-default-features` - KMS-related
> config and `keys.toml` markers still parse in such a build, but any KMS operation reports
> that support isn't compiled in (a KMS wallet opens read-only with a clear log message).

## How it works (envelope encryption)

A keystore wallet's `keys.toml` holds:

- the mnemonic, age-encrypted to a dedicated **x25519 identity** generated at
  init/rewrap time, and
- that identity's secret, **wrapped (encrypted) by your KMS key**, plus the provider,
  key id, and the encryption-context label (the `[kms]` table). Nothing in the file is
  usable without IAM permission to call `Decrypt` on the KMS key.

At startup the daemon makes one KMS `Decrypt` call, recovers the identity in memory,
decrypts the mnemonic, derives the seed, and zeroizes intermediates. The cloud provider
**never sees the mnemonic or seed** - only the random wrap target - so KMS compromise
alone cannot steal funds, and `keys.toml` alone (disk theft, backup leak, snapshot
exfiltration) is useless without the cloud credentials.

The ciphertext is bound to an encryption context (`zecd:wallet`, `zecd:network` - AWS
encryption context / GCP additional authenticated data). Decryption must present the
same values, and on AWS they appear on every CloudTrail entry, so unlocks are
attributable per wallet. The wallet label is fixed at wrap time and stored in
`keys.toml`, so renaming or moving the wallet directory cannot break decryption.

### RPC semantics

In Bitcoin Core terms a keystore wallet is **unencrypted**: it auto-unlocks at startup,
`walletpassphrase`/`walletlock`/`walletpassphrasechange` return `-15`, and
`getwalletinfo` reports no `unlocked_until`. Two transitions exist:

- `encryptwallet "<pass>"` migrates the wallet **off** KMS onto a passphrase (the
  `[kms]` table is dropped; from then on it behaves like any encrypted wallet).
- `zecd rewrap` migrates **onto** the configured keystore from any model (identity
  file, passphrase, or an older KMS key - i.e. it is also the **key rotation** tool).

### Failure behavior

KMS is needed only at unlock time. A running daemon keeps its in-memory seed through a
KMS outage. If KMS is unreachable **at startup**, the wallet comes up locked (reads,
balances, and sync all work; sends return `-13`) and the actor retries the unlock with
exponential backoff (5s → 5min) until it succeeds - a transient KMS/IAM outage heals
without a restart. Each KMS call is bounded by a 15s timeout.

## Setup: AWS KMS

1. Create a symmetric key (HSM-backed by default - AWS KMS keys live in FIPS 140-3
   Level 3 validated HSMs):

   ```sh
   aws kms create-key --description "zecd wallet wrap key"
   aws kms create-alias --alias-name alias/zecd --target-key-id <key-id>
   ```

2. Grant the instance/pod role the minimum:

   ```json
   {
     "Effect": "Allow",
     "Action": ["kms:Encrypt", "kms:Decrypt"],
     "Resource": "arn:aws:kms:us-east-1:111122223333:key/<uuid>",
     "Condition": {
       "StringEquals": { "kms:EncryptionContext:zecd:network": "main" }
     }
   }
   ```

   `kms:Encrypt` is only needed for `init --keystore` / `rewrap`; a steady-state daemon
   role needs `kms:Decrypt` alone. The encryption-context condition is optional but
   pins the key to zecd's use.

3. Configure and initialize:

   ```toml
   [keystore]
   provider = "aws-kms"
   key = "arn:aws:kms:us-east-1:111122223333:key/<uuid>"   # ARN preferred (region comes from it)
   ```

   ```sh
   zecd init --keystore        # new wallet
   zecd rewrap                 # or migrate an existing one
   ```

Credentials use the standard SDK chain: env vars, shared profile, IMDS instance roles,
ECS task roles, and IRSA/EKS web identity all work. Init verifies a full
wrap→unwrap round-trip before writing anything, so an Encrypt-only misconfiguration is
caught immediately rather than at the first restart.

Auditing: every unlock is a CloudTrail `Decrypt` event carrying the
`zecd:wallet`/`zecd:network` encryption context. Alert on `Decrypt` calls from
unexpected principals.

## Setup: Google Cloud KMS

1. Create a key ring and key. For an HSM-protected key (FIPS 140-2 Level 3) it's just a
   flag - no operational difference:

   ```sh
   gcloud kms keyrings create zecd --location us-east1
   gcloud kms keys create wallet-wrap --location us-east1 --keyring zecd \
       --purpose encryption --protection-level hsm
   ```

2. Grant the service account
   `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key (or split: Decrypter for the
   daemon, Encrypter+Decrypter for the host running init/rewrap).

3. Configure:

   ```toml
   [keystore]
   provider = "gcp-kms"
   key = "projects/<p>/locations/us-east1/keyRings/zecd/cryptoKeys/wallet-wrap"
   ```

Credentials use Application Default Credentials: the GCE/GKE metadata server,
`GOOGLE_APPLICATION_CREDENTIALS` service-account keys, workload identity, or gcloud
user credentials. Unlocks appear in Cloud Audit Logs (enable Data Access logs for
Cloud KMS to capture `Decrypt`).

## Key rotation

- **AWS automatic rotation** (and GCP key versions) rotate the *backing material*
  transparently - old ciphertexts keep decrypting, new wraps use the new version. You
  normally don't need to do anything in zecd.
- To move a wallet to a **different key** (or re-wrap under the current one after an
  incident): point `[keystore] key` at the new key and run `zecd rewrap` (it unwraps
  with the old key recorded in `keys.toml`, re-wraps with the configured one, and
  rewrites `keys.toml` atomically). Restart the daemon afterwards.

## Threat model - what this does and doesn't protect

| Protects against | Doesn't protect against |
|---|---|
| Theft of `keys.toml` / backups / disk snapshots | A root attacker on the live, unlocked host reading process memory |
| Offline brute force (no passphrase to guess) | Compromise of cloud credentials that include `kms:Decrypt` **plus** a copy of `keys.toml` |
| Unattended restarts without a human typing a passphrase | RPC-credential theft (an unlocked wallet spends for whoever holds RPC auth) |
| Unauditable unlocks (every Decrypt is logged + IAM-attributed) | |

The seed *is* in zecd's memory while unlocked - same trust model as the identity-file
and unlocked-passphrase models. What changes is custody of the unwrap capability: IAM
instead of a file next to the data, with audit, revocation (cut IAM → next restart
can't unlock), and rotation. The in-memory seed is hardened against *passive* capture
(swap via `mlock`, core dumps via `RLIMIT_CORE=0`, ptrace/`/proc/<pid>/mem` via
`PR_SET_DUMPABLE=0`) - see the README *Security* section. For isolation against an
attacker with code execution inside zecd, pair a watch-only zecd with a separate signer.

**Break-glass recovery:** the mnemonic itself is the recovery path - it is independent
of KMS. If the cloud account is lost, restore with
`zecd init --restore --birthday <h>` from the recorded phrase. Record the phrase at
init time and store it offline; losing both the phrase and KMS access loses the wallet.

## Testing without a cloud account

The `[keystore] endpoint` override points the provider clients at any API-compatible
server:

- **Offline unit/CLI tests** (in this repo) run against in-process fake KMS servers
  (`keystore::fake`) that speak the AWS `x-amz-json-1.1` and GCP REST protocols,
  including encryption-context/AAD mismatch failures - `cargo test`, no network.
- **AWS emulators:** [moto](https://github.com/getmoto/moto) (`pip install
  'moto[server]'; moto_server -p 8080` → `endpoint = "http://localhost:8080"`) and
  [local-kms](https://github.com/nsmithuk/local-kms) (Go binary / docker image,
  supports encryption contexts and a deterministic seed file). LocalStack's community
  images moved behind authentication in March 2026; moto/local-kms avoid that.
  Set dummy `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` so the SDK's chain resolves.
- **GCP emulators:** there is no official Cloud KMS emulator; community options exist
  (e.g. `gcp-kms-emulator`, `fake-cloud-kms`). Alternatively set the
  `ZECD_GCP_ACCESS_TOKEN` env var to any static string to bypass ADC against a fake
  endpoint (test-only - never set it in production).

A full e2e against an emulator looks like:

```sh
moto_server -p 8080 &
KEY=$(AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x aws --endpoint-url http://localhost:8080 \
      --region us-east-1 kms create-key --query KeyMetadata.Arn --output text)
cat > data/zecd.toml <<EOF
network = "regtest"
[keystore]
provider = "aws-kms"
key = "$KEY"
endpoint = "http://localhost:8080"
EOF
AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x zecd --datadir ./data init --keystore
AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x zecd --datadir ./data    # auto-unlocks via "KMS"
```
