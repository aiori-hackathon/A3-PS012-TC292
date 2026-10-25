FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY unbound_open.py /app/unbound_open.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/unbound_open.py"]
