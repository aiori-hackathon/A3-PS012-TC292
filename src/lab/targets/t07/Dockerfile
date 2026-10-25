FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY nsd_server.py /app/nsd_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/nsd_server.py"]
