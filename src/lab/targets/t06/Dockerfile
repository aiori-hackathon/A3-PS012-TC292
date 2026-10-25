FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY dnsmasq_server.py /app/dnsmasq_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/dnsmasq_server.py"]
