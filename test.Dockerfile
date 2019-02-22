FROM vapor/swift:5.0
COPY Sources/ Sources/
COPY Tests/ Tests/
COPY Package.swift Package.swift
ENTRYPOINT swift test
