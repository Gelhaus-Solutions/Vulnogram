FROM --platform=linux/amd64 node:20

# Create unprivileged user

RUN groupadd --system vulnogram && useradd --system --create-home --gid vulnogram vulnogram

WORKDIR /home/vulnogram/
COPY ./package*.json /home/vulnogram/
RUN chown vulnogram:vulnogram --recursive /home/vulnogram/

USER vulnogram
RUN npm install

USER root
COPY . /home/vulnogram/

# Attachment storage dir (opts.conf.files). Created here owned by the vulnogram
# user so an empty named volume mounted at this path inherits writable ownership.
RUN mkdir -p /home/vulnogram/files

RUN chown vulnogram:vulnogram --recursive .
USER vulnogram

CMD ["npm", "start", "--prefix", "/home/vulnogram"]
