FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY kresd_server.py /app/kresd_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/kresd_server.py"]
