#!/bin/sh
# Note: update src/lib.rs when updating URLs/filenames in this file.
set -eu

context_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
staging_dir=$(mktemp -d "${TMPDIR:-/tmp}/ssi-contexts.XXXXXX")
curl_bin=${CURL_BIN:-curl}
trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM

download() {
	url=$1
	output=$2
	"$curl_bin" \
		--fail \
		--location \
		--silent \
		--show-error \
		--retry 3 \
		--retry-all-errors \
		--connect-timeout 20 \
		--max-time 180 \
		--output "$staging_dir/$output" \
		"$url"
}

download https://www.w3.org/2018/credentials/v1 w3c-2018-credentials-v1.jsonld
download https://www.w3.org/2018/credentials/examples/v1 w3c-2018-credentials-examples-v1.jsonld
download https://www.w3.org/ns/odrl.jsonld w3c-odrl.jsonld
download https://schema.org/docs/jsonldcontext.jsonld schema.org.jsonld
download https://w3id.org/security/v1 w3id-security-v1.jsonld
download https://w3id.org/security/v2 w3id-security-v2.jsonld
download https://www.w3.org/ns/did/v1 w3c-did-v1.jsonld
download https://w3id.org/did-resolution/v1 w3c-did-resolution-v1.jsonld
download https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld dif-lds-ecdsa-secp256k1-recovery2020-0.0.jsonld
download https://w3id.org/security/suites/secp256k1recovery-2020/v2 w3id-secp256k1recovery2020-v2.jsonld
download https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json lds-jws2020-v1.jsonld
download https://w3id.org/security/suites/jws-2020/v1 w3id-jws2020-v1.jsonld
download https://w3id.org/security/suites/ed25519-2020/v1 w3id-ed25519-signature-2020-v1.jsonld
download https://w3id.org/security/suites/blockchain-2021/v1 w3id-blockchain-2021-v1.jsonld
download https://w3id.org/citizenship/v1 w3c-ccg-citizenship-v1.jsonld
download https://w3id.org/vaccination/v1 w3c-ccg-vaccination-v1.jsonld
download https://w3id.org/traceability/v1 w3c-ccg-traceability-v1.jsonld
download https://w3id.org/security/bbs/v1 bbs-v1.jsonld
download https://identity.foundation/presentation-exchange/submission/v1 presentation-submission.jsonld
download https://w3id.org/vdl/v1 w3id-vdl-v1.jsonld
download https://w3id.org/wallet/v1 w3id-wallet-v1.jsonld
download https://w3id.org/zcap/v1 w3id-zcap-v1.jsonld
download https://w3id.org/vc-revocation-list-2020/v1 w3id-vc-revocation-list-2020-v1.jsonld
download https://w3id.org/vc/status-list/2021/v1 w3id-vc-status-list-2021-v1.jsonld
download https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json cacao-zcap-v1.jsonld
download https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json jff-vc-edu-plugfest-1-context.json
download https://identity.foundation/linked-vp/contexts/v1 linked-vp-v1.jsonld
download https://identity.foundation/.well-known/did-configuration/v1 did-configuration-v1.jsonld

python3 - "$staging_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted(root.iterdir()):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{path.name}: response is not valid UTF-8 JSON: {error}")
    if not isinstance(document, dict) or "@context" not in document:
        raise SystemExit(f"{path.name}: response is not a JSON-LD context object")
PY

# Do not touch tracked contexts until every remote response has passed validation.
for staged_file in "$staging_dir"/*; do
	cp "$staged_file" "$context_dir/$(basename "$staged_file")"
done
