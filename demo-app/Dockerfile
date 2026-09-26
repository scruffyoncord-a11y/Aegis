# Aegis demo target -- built and run only inside Aegis's own disposable
# sandbox, never exposed or deployed anywhere else.
#
# NOTE: we deliberately do NOT `npm install` from package.json here.
# package.json intentionally lists a non-existent package (for Aegis's
# own Phase 2 "hallucinated dependency" test) plus a pinned-vulnerable
# express/lodash version (for the Phase 2 CVE test) -- installing it
# literally would fail the build on the fake package. We only install
# the one real package app.js actually requires to run.

FROM node:20-slim

WORKDIR /app
COPY app.js .

RUN npm install --no-save express@4.18.2

EXPOSE 3001
CMD ["node", "app.js"]
