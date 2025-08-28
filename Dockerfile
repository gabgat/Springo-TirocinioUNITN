FROM python:3.13.7-trixie
LABEL authors="InternetSpringo"

ENV DEBIAN_FRONTEND=noninteractive
ENV OUTPUT_DIR=/app/outputs

WORKDIR /app

# Create output directory
RUN mkdir -p /app/outputs

# Install prerequisites and add Kali GPG key first
RUN apt-get update && \
    apt-get install -y gnupg curl && \
    curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/kali.gpg

# Add Kali repositories after GPG key is installed
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
    > /etc/apt/sources.list.d/kali.list

# Optional: Pin priorities (prefer Debian packages unless explicitly asked from Kali)
RUN echo "Package: *\nPin: release o=Kali\nPin-Priority: 100\n" \
    > /etc/apt/preferences.d/kali.pref

# Update package lists and install security tools
RUN apt-get update && apt-get install -y nmap  \
    nikto \
    whatweb \
    sslscan \
    ffuf  \
    hydra \
    ssh-audit \
    enum4linux-ng \
    wpscan  \
    dnsutils \
    && apt-get clean

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Use ENTRYPOINT + CMD to allow arguments
ENTRYPOINT ["python3", "main.py"]
CMD []