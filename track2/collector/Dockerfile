FROM python:3.12-slim

# No build tooling, no shell utilities: the gateway only forwards and appends.
WORKDIR /app

RUN pip install --no-cache-dir "fastapi==0.111.0" "uvicorn[standard]==0.30.1" "httpx==0.27.0" "aiohttp==3.14.3" "requests==2.32.5"
RUN pip install --no-cache-dir "onnxruntime==1.23.2" "tokenizers==0.22.1" "numpy==2.2.6"
RUN pip install --no-cache-dir "msgspec==0.21.1"

COPY collector/gateway.py collector/inline_guard.py collector/upstream.py collector/native_stack.py ./
# The detector is imported, never forked. A second copy of the rules would drift,
# and the drift would be silent -- a failure this project has already paid for three
# separate times with duplicated definitions and duplicated vocabularies.
COPY detector/session.py detector/rules.py detector/task_policy.py detector/knowledge_graph.py ./detector/
COPY detector/generalization.py detector/security_graph.py detector/intervention.py ./detector/
COPY detector/runtime_r10.py detector/semantic_model.py detector/business_flow.py detector/trusted_plan.py detector/controlled_executor.py ./detector/
COPY collector/control_endpoint.py ./
COPY collector/model_proposer.py collector/pooled_transport.py ./
COPY collector/json_codec.py ./
COPY detector/action_intent.py detector/contextual_intent.py detector/sparse_injection_model.py detector/execution_contract.py detector/model_controlled_executor.py ./detector/
COPY detector/source_contract.py ./detector/
COPY models/r10 ./models/r10/
COPY models/r11_sparse ./models/r11_sparse/
RUN touch ./detector/__init__.py

# Evidence lands on a mounted volume so it survives container restarts and can be
# analysed from the host without docker exec.
ENV RECORD_DIR=/evidence
RUN mkdir -p /evidence

EXPOSE 8080
CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "warning"]
