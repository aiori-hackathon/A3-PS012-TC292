FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY truncate_server.py /app/truncate_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/truncate_server.py"]
