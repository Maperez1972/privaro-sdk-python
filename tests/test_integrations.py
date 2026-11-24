"""Integration adapters + path regression tests (HTTP mocked)."""
import json
from unittest.mock import patch

import pytest

from privaro.client import PrivaroClient
from privaro.models import RetrievalChunk

KEY = "prvr_" + "a" * 40
calls = []


class _Resp:
    def __init__(self, body): self._b = json.dumps(body).encode()
    def read(self): return self._b
    def __enter__(self): return self
    def __exit__(self, *a): return False


def fake_urlopen(req, timeout=None):
    body = json.loads(req.data.decode())
    calls.append((req.full_url, body))
    u = req.full_url
    if u.endswith("/proxy/protect"):
        return _Resp({"request_id": "r", "protected_prompt": body["prompt"].replace("Ana", "[NM-0001]"), "detections": []})
    if u.endswith("/proxy/protect-tool-output"):
        return _Resp({"protected_output": {"n": "[NM-0001]"}, "detections_count": 1, "fields_protected": ["n"]})
    if u.endswith("/proxy/detokenize"):
        return _Resp({"detokenized_text": body["text"].replace("[NM-0001]", "Ana")})
    if u.endswith("/proxy/protect-retrieval"):
        ok = [c for c in body["chunks"] if c.get("allowed_roles") in (None, ["developer"])]
        return _Resp({"request_id": "r", "allowed_chunks": [{"id": c["id"], "protected_text": c["text"].replace("Ana", "[NM-0001]"), "detections_count": 1} for c in ok],
                      "blocked_chunks": [], "stats": {}})
    raise AssertionError("unexpected url " + u)


@pytest.fixture(autouse=True)
def _patch():
    calls.clear()
    with patch("urllib.request.urlopen", fake_urlopen):
        yield


@pytest.fixture
def client():
    return PrivaroClient(api_key=KEY, pipeline_id="p1")


def test_no_double_v1_in_paths(client):
    client.protect_retrieval([RetrievalChunk(id="1", text="Ana")])
    client.detokenize("x [NM-0001]", "c1")
    assert all("/v1/v1/" not in u for u, _ in calls)
    assert calls[0][0] == "https://api.privaro.ai/v1/proxy/protect-retrieval"


def test_detokenize(client):
    assert client.detokenize("Hola [NM-0001]", "c1") == "Hola Ana"
    assert calls[-1][1]["conversation_id"] == "c1"


def test_langchain_guard_and_rag(client):
    lc = pytest.importorskip("langchain_core")
    from langchain_core.documents import Document
    from langchain_core.messages import HumanMessage
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.runnables import RunnableLambda
    from privaro.integrations.langchain import PrivaroDocumentTransformer, PrivaroRetriever, privaro_guard, privaro_mask

    seen = {}
    llm = RunnableLambda(lambda s: (seen.setdefault("in", s), "Hola " + s.split()[-1])[1])
    assert privaro_guard(llm, client).invoke("Soy Ana") == "Hola Ana"
    assert seen["in"] == "Soy [NM-0001]"
    assert len({b["conversation_id"] for _, b in calls if "conversation_id" in b}) == 1
    assert privaro_mask(client).invoke([HumanMessage(content="Soy Ana")])[0].content == "Soy [NM-0001]"
    d = PrivaroDocumentTransformer(client).transform_documents([Document(page_content="Ana vive aquí")])
    assert d[0].page_content == "[NM-0001] vive aquí" and d[0].metadata["privaro_masked"]

    class Base(BaseRetriever):
        def _get_relevant_documents(self, query, *, run_manager=None):
            return [Document(page_content="Ana"), Document(page_content="Ana secreto", metadata={"allowed_roles": ["admin"]})]
    assert [x.page_content for x in PrivaroRetriever(Base(), client).invoke("q")] == ["[NM-0001]"]


def test_llamaindex(client):
    pytest.importorskip("llama_index.core")
    from llama_index.core.schema import NodeWithScore, TextNode
    from privaro.integrations.llamaindex import PrivaroNodePostprocessor, PrivaroTransform

    nodes = [NodeWithScore(node=TextNode(text="Ana Pérez"), score=0.9),
             NodeWithScore(node=TextNode(text="x Ana", metadata={"allowed_roles": ["admin"]}), score=0.5)]
    res = PrivaroNodePostprocessor(client).postprocess_nodes(nodes)
    assert len(res) == 1 and res[0].node.get_content() == "[NM-0001] Pérez" and res[0].score == 0.9
    assert PrivaroTransform(client)([TextNode(text="Ana")])[0].get_content() == "[NM-0001]"


def test_protect_tool_output(client):
    r = client.protect_tool_output({"n": "Ana"}, "c1", tool_name="crm")
    assert r["protected_output"] == {"n": "[NM-0001]"}
    assert calls[-1][1]["tool_name"] == "crm" and calls[-1][1]["conversation_id"] == "c1"
