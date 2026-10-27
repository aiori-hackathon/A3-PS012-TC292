FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython PyYAML
COPY authzone_server.py /app/authzone_server.py
RUN mkdir -p /var/log/authzone
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/authzone_server.py"]
