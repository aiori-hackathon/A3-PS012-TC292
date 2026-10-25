FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY forwarder_closed.py /app/forwarder_closed.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/forwarder_closed.py"]
