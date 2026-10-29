# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL IMAGE v4.6.11-TRACE
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
# ============================================================================
FROM python:3.11-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
RUN apt-get update \
 && apt-get install -y --no-install-recommends iw libpcap0.8 ieee-data \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir 'scapy>=2.5,<3'
WORKDIR /opt/bci
COPY sentinel_exporter.py /opt/bci/sentinel_exporter.py
CMD ["python3", "-u", "/opt/bci/sentinel_exporter.py"]
