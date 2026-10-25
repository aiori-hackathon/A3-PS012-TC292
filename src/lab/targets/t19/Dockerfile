FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY packetloss_server.py /app/packetloss_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/packetloss_server.py"]
