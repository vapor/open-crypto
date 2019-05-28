FROM swift:5.0-bionic
COPY Sources/ Sources/
COPY Tests/ Tests/
COPY Package.swift Package.swift
RUN apt-get -y install openssl libssl-dev
ENTRYPOINT swift build -v
