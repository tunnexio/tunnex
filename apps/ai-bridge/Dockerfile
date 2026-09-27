FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LITELLM_LOCAL_MODEL_COST_MAP=true DO_NOT_TRACK=1 AWS_EC2_METADATA_DISABLED=true
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY bridge.py worker.py transport.py diagnostics.py LICENSE.litellm ./
USER 65532:65532
EXPOSE 8200
CMD ["python", "/app/bridge.py"]
