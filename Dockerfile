FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
EXPOSE 8787
ENTRYPOINT ["mcp-sentry"]
CMD ["bench"]
