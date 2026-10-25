FROM python:3.11-slim
COPY drop_server.py /app/drop_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/drop_server.py"]
