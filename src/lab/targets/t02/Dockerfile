FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY bind_closed.py /app/bind_closed.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/bind_closed.py"]
