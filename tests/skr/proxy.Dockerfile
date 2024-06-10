
FROM python:latest
WORKDIR /usr/src/app

# Install gRPCurl
RUN wget -q https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz &&\
    tar xfz grpcurl_1.8.7_linux_x86_64.tar.gz &&\
    chmod +x grpcurl &&\
    cp grpcurl /bin/ &&\
    rm -f grpcurl*

RUN pip install flask requests
COPY proxy.py .

CMD ["python3", "proxy.py"]