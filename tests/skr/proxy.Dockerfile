
FROM mcr.microsoft.com/cbl-mariner/base/python:3.9
WORKDIR /usr/src/app

# Install wget & tar
RUN tdnf update -y && tdnf upgrade -y && tdnf install -y wget tar && tdnf clean all

# Install gRPCurl
RUN wget --no-check-certificate https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz && \
    tar xfz grpcurl_1.8.7_linux_x86_64.tar.gz && \
    chmod +x grpcurl && \
    cp grpcurl /bin/ && \
    rm -f grpcurl*

RUN pip install flask requests
COPY proxy.py .

CMD ["python3", "proxy.py"]