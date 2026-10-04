# Layer 2 of Shadow Strike's isolation (layer 1 is sandbox.py's rlimits).
# Builds a minimal, non-root, read-only-filesystem container to run
# ForgeRunner in. Network access is restricted to the single RPC host
# passed in at run time — nothing else resolves.
#
# Build: docker build -f docker/sandbox.Dockerfile -t shadow-strike-sandbox .
# Run:   docker run --rm \
#          --read-only --tmpfs /tmp:rw,size=256m \
#          --memory=1g --cpus=1 \
#          --cap-drop=ALL --security-opt=no-new-privileges \
#          --network=shadow-strike-egress \
#          -e MAINNET_RPC_URL=$MAINNET_RPC_URL \
#          -v "$(pwd)/contracts:/workspace/contracts:ro" \
#          shadow-strike-sandbox \
#          forge test --match-contract ShadowStrike_scn_xxxx --fork-url $MAINNET_RPC_URL -vvvv --json

FROM ghcr.io/foundry-rs/foundry:latest AS foundry

FROM debian:bookworm-slim

RUN groupadd --gid 10001 shadowstrike \
    && useradd --uid 10001 --gid shadowstrike --no-create-home --shell /usr/sbin/nologin shadowstrike

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast

WORKDIR /workspace
# contracts/ is bind-mounted read-only at run time (see the `docker run`
# example above) — nothing baked into the image is treated as trusted
# beyond forge/anvil/cast themselves.

USER shadowstrike
ENTRYPOINT ["forge"]
