FROM python:3.12-slim AS builder
WORKDIR /app

# xmlsec1 is required by python3-saml for SAML signature validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxmlsec1-dev \
    libxml2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime image — slim with non-root user
# Note: distroless is incompatible with xmlsec1 native libs required by python3-saml
FROM python:3.12-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --shell /bin/false sextant

COPY --from=builder /install /usr/local
COPY app/ app/

USER sextant
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
