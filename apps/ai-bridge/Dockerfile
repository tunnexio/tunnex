FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LITELLM_LOCAL_MODEL_COST_MAP=true DO_NOT_TRACK=1 AWS_EC2_METADATA_DISABLED=true
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY bridge.py worker.py transport.py LICENSE.litellm ./
USER 65532:65532
EXPOSE 8200
CMD ["python", "/app/bridge.py"]
