FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    LITELLM_LOCAL_MODEL_COST_MAP=true DO_NOT_TRACK=1 \
    DISABLE_ADMIN_UI=true DISABLE_SCHEMA_UPDATE=true \
    AWS_EC2_METADATA_DISABLED=true XDG_CACHE_HOME=/tmp/cache \
    PRISMA_BINARY_CACHE_DIR=/opt/prisma-binaries
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
# Generate the client at build time: non-root/read-only startup cannot write to
# site-packages. This generates code and downloads Prisma's versioned engines;
# it does not connect to a database or run schema migrations.
RUN python -c 'import importlib.util, pathlib, subprocess; spec = importlib.util.find_spec("litellm"); schema = pathlib.Path(spec.origin).parent / "proxy/schema.prisma"; subprocess.run(["prisma", "generate", "--schema", str(schema)], check=True)' \
    && chmod -R a+rX /opt/prisma-binaries
COPY config.yaml entrypoint.py LICENSE.litellm LICENSE.litellm-proxy-extras ./
USER 65532:65532
EXPOSE 4000
ENTRYPOINT ["python", "/app/entrypoint.py"]
