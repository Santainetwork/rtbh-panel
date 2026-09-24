# syntax=docker/dockerfile:1
# Reference image only. Build context and binary packaging belong to the application release.
FROM scratch

# The application must contain the native in-process BGP listener.
# Production listens on TCP/179. Publish it narrowly and enforce listen_ranges.
EXPOSE 179/tcp

# Replace with the release binary path when packaging the application.
ENTRYPOINT ["/rtbh-panel"]
