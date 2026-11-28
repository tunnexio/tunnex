# Example application image for a Tunnex AI Gateway workload.
# Copy the `tunnex` Linux binary from the Tunnex release into the build context.
FROM python:3.12-slim
RUN useradd --uid 10001 --create-home app \
 && install -d -m 0700 -o 10001 -g 10001 /run/secrets/tunnex /var/lib/tunnex-workload
COPY tunnex /usr/local/bin/tunnex
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY app.py /app/app.py
RUN pip install --no-cache-dir openai
WORKDIR /app
USER 10001:10001
# Kubernetes overrides this with the manifest's command; ECS and Docker use it.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "app.py"]
