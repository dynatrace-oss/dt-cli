FROM python:3.9-slim

# Install package build system
RUN pip install poetry
RUN apt-get update && apt-get install -y binutils patchelf

# Project directory must be mounted in /app
WORKDIR /app

COPY poetry.lock /app/
COPY pyproject.toml.mod /app/pyproject.toml
RUN poetry config virtualenvs.create false && poetry install --no-root

COPY . .

CMD [ "tail", "-f", "/dev/null" ]
