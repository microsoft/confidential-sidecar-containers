FROM python:latest
WORKDIR /usr/src/app

RUN pip install flask requests
COPY proxy.py .

CMD ["python3", "proxy.py"]