FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY pdns_server.py /app/pdns_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/pdns_server.py"]
