FROM python:3.11-slim
RUN pip install --no-cache-dir dnspython
COPY unbound_refused.py /app/unbound_refused.py
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "/app/unbound_refused.py"]
