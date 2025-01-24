FROM cgr.dev/chainguard/python:latest-dev AS builder
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /flask-app
ENV PATH="/flask-app/venv/bin":$PATH
RUN python -m venv venv

COPY src/python/requirements.txt requirements.txt
RUN pip install -r requirements.txt

FROM cgr.dev/chainguard/glibc-dynamic:latest-dev

#Run as root for access to docker / containerd
USER root
RUN apk add --no-cache syft ctr docker-cli python-3.13 nano jq

ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/flask-app/venv/bin":$PATH

WORKDIR /flask-app

COPY --from=builder /flask-app/venv /flask-app/venv
COPY src/python/*.py ./
COPY src/python/*.yaml ./
COPY src/shell/* ./

EXPOSE 8080
ENTRYPOINT ["python", "-m", "gunicorn", "--timeout", "6000", "-b", "0.0.0.0:8080", "web_app:app"]
