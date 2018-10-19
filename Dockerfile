FROM busybox 
COPY auth_server /home/docker_auth/
#for use busybox, set CGO_ENABLED=0, use go build -a to compile
ENTRYPOINT ["/home/docker_auth/auth_server"]
CMD ["/home/docker_auth/config/auth_config.yml"]
EXPOSE ["5002"]
