# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="dc09-receiver" \
      org.opencontainers.image.description="ANSI/SIA DC-09 alarm receiver" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[aes]" && rm /tmp/*.whl \
 && useradd --system --uid 10001 --home /data dc09 && mkdir -p /data && chown dc09 /data
USER dc09
WORKDIR /data
EXPOSE 9500/tcp 9500/udp
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import socket; socket.create_connection(('127.0.0.1', 9500), 3).close()"
ENTRYPOINT ["dc09-receiver"]
CMD ["serve"]
