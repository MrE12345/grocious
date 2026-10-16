ARG LOGIN_IMAGE=grocery-login:latest
FROM ${LOGIN_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.1.3 cryptography==43.0.3 gunicorn==26.2.0 requests==2.34.2 playwright==1.63.0
RUN python -m playwright install --with-deps chromium && chmod -R a+rX /ms-playwright
COPY app/ /app/
COPY LICENSE NOTICE README.md /source/
COPY app/ /source/app/
COPY tests/ /source/tests/
COPY Dockerfile /source/Dockerfile
WORKDIR /app
ENV PYTHONUNBUFFERED=1 GROCIOUS_DATA=/data
USER 1001:100
ENTRYPOINT []
CMD ["gunicorn", "--bind=0.0.0.0:3015", "--workers=1", "--threads=12", "--timeout=60", "--graceful-timeout=15", "--worker-tmp-dir=/tmp", "--no-control-socket", "--access-logfile=/dev/null", "service:app"]
