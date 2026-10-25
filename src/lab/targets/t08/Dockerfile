FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY knot_server.py /app/knot_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/knot_server.py"]
