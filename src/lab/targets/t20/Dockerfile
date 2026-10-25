FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY auth_refuse_server.py /app/auth_refuse_server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/auth_refuse_server.py"]
