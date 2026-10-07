FROM python:3.12-slim

# Build context is `track2/`, not `track2/inventory/`, so that the capability table
# can be copied from the detector instead of forked into a second copy. Two copies of
# a capability table drift, and a drifted table silently mis-classifies assets.
RUN pip install --no-cache-dir "httpx==0.27.0"

# No docker CLI: the scanner talks to the engine over the socket API directly.
# Installing docker.io from Debian left the CLI off PATH and silently emptied the
# whole service inventory, which in turn silenced every configuration finding.

WORKDIR /app
COPY inventory/scanner.py inventory/risks.py inventory/detector_bridge.py inventory/run_scan.py ./
# codecap reads a tool's IMPLEMENTATION rather than its declaration. Omitting it did
# not fail the build: the scanner simply reported zero code-derived capabilities and
# silently fell back to declarations -- exactly the degradation this module exists to
# prevent, and the third time in this project that a missing file looked like a clean
# result rather than an error.
COPY inventory/codecap.py inventory/source_profiles.py inventory/source_registry.py ./
COPY detector/session.py ./detector/session.py
RUN touch ./detector/__init__.py

RUN mkdir -p /evidence /range
CMD ["python", "run_scan.py", "--out", "/evidence/inventory.json"]
