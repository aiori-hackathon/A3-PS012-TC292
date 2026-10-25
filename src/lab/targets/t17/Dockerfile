FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY lying_server.py /app/lying_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/lying_server.py"]
