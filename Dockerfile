# Define custom function directory
ARG FUNCTION_DIR="/function"

FROM python:3.10-slim-bookworm AS build-image

# Include global arg in this stage of the build
ARG FUNCTION_DIR

RUN apt-get update && \
apt-get install -y --no-install-recommends nmap && \
rm -rf /var/lib/apt/lists/*

# Install aws-lambda-cpp build dependencies

RUN apt-get update && \
  apt-get install -y \
  g++ \
  make \
  cmake \
  unzip \
  git \
  libcurl4-openssl-dev \
  glibc-source

# Copy function code
RUN mkdir -p ${FUNCTION_DIR}

# Update pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install the function's dependencies
RUN pip install --no-cache-dir \
    --target ${FUNCTION_DIR} \
        awslambdaric \
        boto3 \
        redis \
        httplib2 \
        requests \
        numpy \
        scipy \
        pandas \
        pika \
        kafka-python \
        cloudpickle \
        ps-mem \
        tblib \
        delegator.py \
	invoke

FROM python:3.10-slim-bookworm

# Include global arg in this stage of the build
ARG FUNCTION_DIR
# Set working directory to function root directory
WORKDIR ${FUNCTION_DIR}

ENV HOME=/root
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Copy in the built dependencies
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}

RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*

# Add Lithops
COPY lithops_lambda.zip ./
RUN unzip lithops_lambda.zip \
    && rm lithops_lambda.zip \
    && mkdir handler \
    && touch handler/__init__.py \
    && mv entry_point.py handler/

# Put your dependencies/tools here, using RUN pip install... or RUN apt install...

RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && rm -rf /var/lib/apt/lists/*

# install go
RUN wget  https://dl.google.com/go/go1.22.4.linux-amd64.tar.gz
RUN tar -xvf go1.22.4.linux-amd64.tar.gz
RUN rm go1.22.4.linux-amd64.tar.gz
RUN mv go /usr/local

# ENV for Go
ENV GOROOT="/usr/local/go"
ENV PATH="${PATH}:${GOROOT}/bin"
ENV PATH="${PATH}:${GOPATH}/bin"
ENV GOPATH=$HOME/go

ENV HOME="/tmp"
RUN mkdir "/tmp/.config"
RUN chmod -R a+rwx "/tmp"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

RUN go install github.com/d3mondev/puredns/v2@latest

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN go install github.com/hahwul/dalfox/v2@latest

RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

RUN go install -v github.com/ffuf/ffuf@latest

RUN go install -v github.com/tomnomnom/fff@latest

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates

RUN apt-get update && apt-get install --no-install-recommends curl ca-certificates && \
    rm -rf /static-nmap && \
    mkdir -p /static-nmap && \
    curl -fsSL https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/nmap -o /static-nmap/nmap && \
    chmod +x /static-nmap/nmap

RUN  curl -o /function/resolvers.txt -LO https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt

ENTRYPOINT [ "/usr/local/bin/python", "-m", "awslambdaric" ]

CMD [ "handler.entry_point.lambda_handler" ]

