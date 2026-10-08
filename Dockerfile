# Fedora 44 runtime matches the Fedora 44 host used for the local hackathon lab.
# Compile first with: cargo build --release -p logshield-api -p logshield-lab
FROM fedora:44
RUN mkdir -p /logs /state && chown -R 10001:10001 /logs /state
COPY target/release/logshield-api /usr/local/bin/logshield-api
COPY target/release/logshield-lab /usr/local/bin/logshield-lab
USER 10001:10001
EXPOSE 8080 3000
