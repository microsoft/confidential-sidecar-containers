FROM ubuntu
RUN apt-get -y update && apt-get -y install nginx python3

WORKDIR /app

# copy all files from this folder to working directory (ignores files in .dockerignore)
COPY . /app/
RUN mv default /etc/nginx/sites-available/default

EXPOSE 80
EXPOSE 443
ENV PYTHONUNBUFFERED=1

RUN rm -rf /usr/share/nginx/html/
# entrypoint
CMD [ "python3", "main.py"]
