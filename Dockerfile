FROM python:3.14-rc-slim-trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.14-rc-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

#Adding kali's repos and tools + cleanup
RUN apt-get update && \
    apt-get install -y --no-install-recommends gnupg curl ca-certificates && \
    curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/kali.gpg && \
    echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list.d/kali.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        whatweb \
        sslscan \
        ffuf \
        hydra \
        ssh-audit \
        enum4linux-ng \
        wpscan \
        dnsutils \
    && \
    apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* \
           /var/cache/apt/archives/* \
           /var/cache/debconf/* \
           /usr/share/doc/* \
           /usr/share/man/* \
           /usr/share/info/* \
           /usr/share/locale/* \
           /usr/share/lintian/* \
           /usr/share/common-licenses/* \
           /tmp/* \
           /var/tmp/* \
           /root/.cache/* && \
    apt-get purge -y --auto-remove gnupg curl && \
    find /usr/lib/python*/dist-packages/ -name "*.pyc" -delete && \
    find /usr/lib/python*/dist-packages/ -name "__pycache__" -delete

WORKDIR /app
RUN mkdir -p outputs

COPY . .

ENTRYPOINT ["python3", "main.py"]
CMD []