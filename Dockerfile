FROM --platform=$BUILDPLATFORM alpine:latest

ARG TARGETOS
ARG TARGETARCH

COPY dist/app-${TARGETOS}-${TARGETARCH} /usr/local/bin/oidc-playground
COPY build/default-config.json /etc/idp/config.json

ENV IDP_CONFIG_PATH=/etc/idp/config.json
EXPOSE 8080

ENTRYPOINT ["oidc-playground"]