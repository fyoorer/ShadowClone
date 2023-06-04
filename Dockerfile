# Define custom function directory
ARG FUNCTION_DIR="/function"

FROM python:3.9-buster as build-image

# Include global arg in this stage of the build
ARG FUNCTION_DIR

# Install aws-lambda-cpp build dependencies
RUN apt-get update && \
  apt-get install -y \
  g++ \
  make \
  cmake \
  unzip \
  git \
  libcurl4-openssl-dev

# Copy function code
RUN mkdir -p ${FUNCTION_DIR}

# Update pip
RUN pip install -U pip wheel six setuptools

# Install the function's dependencies
RUN pip install \
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
        delegator.py


FROM python:3.9-buster

# Include global arg in this stage of the build
ARG FUNCTION_DIR
# Set working directory to function root directory
WORKDIR ${FUNCTION_DIR}

# Copy in the built dependencies
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}

# Add Lithops
COPY lithops_lambda.zip ${FUNCTION_DIR}
RUN unzip lithops_lambda.zip \
    && rm lithops_lambda.zip \
    && mkdir handler \
    && touch handler/__init__.py \
    && mv entry_point.py handler/

# Put your dependencies/tools here, using RUN pip install... or RUN apt install...


# install go
RUN wget https://dl.google.com/go/go1.19.5.linux-amd64.tar.gz
RUN tar -xvf go1.19.5.linux-amd64.tar.gz
RUN rm go1.19.5.linux-amd64.tar.gz
RUN mv go /usr/local

# ENV for Go
ENV GOROOT="/usr/local/go"
ENV PATH="${PATH}:${GOROOT}/bin"
ENV PATH="${PATH}:${GOPATH}/bin"
ENV GOPATH=$HOME/go

RUN go install github.com/d3mondev/puredns/v2@latest

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN go install github.com/hahwul/dalfox/v2@latest

RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

RUN go install -v github.com/ffuf/ffuf@latest

RUN go install -v github.com/tomnomnom/fff@latest

RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates

RUN git clone https://github.com/0xjbb/static-nmap.git /static-nmap && chmod +x /static-nmap/nmap

RUN git clone https://github.com/robertdavidgraham/masscan /masscan && cd /masscan && make 

# RUN curl -LO https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz && tar xvf kiterunner_1.0.2_linux_amd64.tar.gz 

RUN  curl -o /function/resolvers.txt -LO https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt

COPY ./bin/massdns /usr/local/bin/massdns

# install massdns
# RUN git clone https://github.com/blechschmidt/massdns.git
# RUN cd massdns && make && cp bin/massdns /usr/local/bin/massdns


ENTRYPOINT [ "/usr/local/bin/python", "-m", "awslambdaric" ]
CMD [ "handler.entry_point.lambda_handler" ]
