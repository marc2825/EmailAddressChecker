FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml LICENSE /app/
COPY docs/pypi.md /app/docs/pypi.md
COPY src /app/src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

USER 65532:65532

ENTRYPOINT ["emailcheck"]
CMD ["--version"]
