FROM python:latest

# Install package build system
RUN pip install poetry

# Project directory must be mounted in /app
WORKDIR /app

COPY . .
RUN poetry install

CMD [ "tail", "-f", "/dev/null" ]
