# Use Python 3.11 slim as base
FROM python:3.11-slim

# Install system dependencies: tshark
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# Fix: Ensure wireshark group exists (sometimes not created non-interactively)
# and set up permissions for dumpcap
RUN groupadd -f wireshark && \
    useradd -m -g wireshark appuser && \
    chown root:wireshark /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure upload directory exists and is writable
RUN mkdir -p uploads && chown -R appuser:wireshark /app

# Switch to non-privileged user
USER appuser

# Expose port
EXPOSE 8000

# Start command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
