FROM fullstorydev/grpcurl:v1.9.1 as grpcurl-builder

FROM python:latest
WORKDIR /usr/src/app

# Install gRPCurl
COPY --from=grpcurl-builder /bin/grpcurl /usr/local/bin/grpcurl
RUN chmod +x /usr/local/bin/grpcurl

RUN pip install flask requests
COPY proxy.py .

CMD ["python3", "proxy.py"]