FROM quay.io/fedora/fedora:44
RUN mkdir -p /state /logs && chown -R 10001:10001 /state /logs
COPY target/release/logshield-api /usr/local/bin/logshield-api
RUN chmod 755 /usr/local/bin/logshield-api
USER 10001:10001
EXPOSE 3000
