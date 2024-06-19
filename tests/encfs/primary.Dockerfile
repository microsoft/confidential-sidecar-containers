FROM python:latest
WORKDIR /usr/src/app

RUN pip install flask

COPY primary.py .

CMD ["python3", "primary.py"]

