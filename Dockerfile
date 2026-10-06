# tessera-signer: one key share behind a policy-enforcing HTTP API.
#
#   docker run -v /srv/signer:/etc/tessera -e TESSERA_PASSPHRASE -e TESSERA_TOKEN \
#     -p 7401:7401 ghcr.io/use-tessera/tessera-signer
#
# /etc/tessera holds signer.toml, the share, the policy and state_dir.
FROM rust:1.97-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tessera-signer --bin tessera-signer

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/tessera-signer /usr/local/bin/tessera-signer
WORKDIR /etc/tessera
EXPOSE 7401
ENTRYPOINT ["/usr/local/bin/tessera-signer"]
CMD ["--config", "/etc/tessera/signer.toml"]
