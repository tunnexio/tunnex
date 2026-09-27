FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
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
# Prisma bootstraps Node for code generation; pin supported LTS instead of latest.
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/*
RUN python -m nodeenv --node=24.21.0 /opt/prisma-node
RUN PATH="/opt/prisma-node/bin:$PATH" python -c 'import importlib.util, pathlib, subprocess; spec = importlib.util.find_spec("litellm"); schema = pathlib.Path(spec.origin).parent / "proxy/schema.prisma"; subprocess.run(["prisma", "generate", "--schema", str(schema)], check=True)' \
    && chmod -R a+rX /opt/prisma-binaries
COPY config.yaml entrypoint.py LICENSE.litellm LICENSE.litellm-proxy-extras ./
USER 65532:65532
EXPOSE 4000
ENTRYPOINT ["python", "/app/entrypoint.py"]
