"""
LangChain adapters (langchain-core >= 0.2).  pip install "privaro[langchain]"

    from privaro import PrivaroClient
    from privaro.integrations.langchain import privaro_guard, PrivaroDocumentTransformer, PrivaroRetriever

    client = PrivaroClient(api_key="prvr_...", pipeline_id="...")
    chain = privaro_guard(prompt | llm | StrOutputParser(), client)      # mask in -> LLM -> reveal out
    docs  = PrivaroDocumentTransformer(client).transform_documents(raw)  # mask before embedding
    rag   = PrivaroRetriever(vectorstore.as_retriever(), client)         # mask retrieved chunks (+ allowed_roles ACL)

Why not a callback handler? LangChain callbacks cannot rewrite what a model receives
(PrivaroCallbackHandler in privaro.agent does not protect chat models) — Runnables do.
"""
from __future__ import annotations

import uuid
from typing import Any, List, Optional, Sequence

from langchain_core.documents import BaseDocumentTransformer, Document
from langchain_core.retrievers import BaseRetriever
from langchain_core.runnables import Runnable, RunnableLambda

from privaro.client import PrivaroClient
from privaro.models import RetrievalChunk


def _mask(client: PrivaroClient, cid: str, v: Any) -> Any:
    if isinstance(v, str):
        return client.protect(v, conversation_id=cid, include_detections=False).protected if v.strip() else v
    if isinstance(v, dict):
        return {k: _mask(client, cid, x) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask(client, cid, x) for x in v]
    if hasattr(v, "to_messages"):                                   # PromptValue
        return [_mask(client, cid, m) for m in v.to_messages()]
    if hasattr(v, "content") and isinstance(v.content, str):        # BaseMessage
        return v.model_copy(update={"content": _mask(client, cid, v.content)})
    return v


def privaro_mask(client: PrivaroClient, conversation_id: Optional[str] = None) -> Runnable:
    """Runnable that masks every string in its input (str | dict | list | messages | PromptValue)."""
    cid = conversation_id or str(uuid.uuid4())
    return RunnableLambda(lambda v: _mask(client, cid, v), name="PrivaroMask")


def privaro_unmask(client: PrivaroClient, conversation_id: str) -> Runnable:
    def _un(v: Any) -> Any:
        if isinstance(v, str):
            return client.detokenize(v, conversation_id)
        if hasattr(v, "content") and isinstance(v.content, str):
            return v.model_copy(update={"content": client.detokenize(v.content, conversation_id)})
        return v
    return RunnableLambda(_un, name="PrivaroUnmask")


def privaro_guard(chain: Runnable, client: PrivaroClient, conversation_id: Optional[str] = None) -> Runnable:
    """mask -> chain -> unmask, sharing ONE conversation id."""
    cid = conversation_id or str(uuid.uuid4())
    return privaro_mask(client, cid) | chain | privaro_unmask(client, cid)


def _protect_docs(client: PrivaroClient, docs: Sequence[Document], role: str) -> List[Document]:
    out: List[Document] = []
    for s in range(0, len(docs), 200):
        batch = docs[s:s + 200]
        res = client.protect_retrieval(
            [RetrievalChunk(id=str(i), text=d.page_content, allowed_roles=d.metadata.get("allowed_roles")) for i, d in enumerate(batch)],
            requester_role=role)
        by_id = {c.id: c.protected_text for c in res.allowed_chunks}
        out += [Document(page_content=by_id[str(i)], metadata={**d.metadata, "privaro_masked": True})
                for i, d in enumerate(batch) if str(i) in by_id]
    return out


class PrivaroDocumentTransformer(BaseDocumentTransformer):
    """Mask documents before they are embedded/stored (ingestion pipelines)."""

    def __init__(self, client: PrivaroClient, role: str = "developer"):
        self.client, self.role = client, role

    def transform_documents(self, documents: Sequence[Document], **kwargs: Any) -> List[Document]:
        return _protect_docs(self.client, documents, self.role)


class PrivaroRetriever(BaseRetriever):
    """Wrap any retriever: retrieved chunks are masked and `allowed_roles` metadata is enforced."""

    base: Any
    client: Any
    role: str = "developer"

    def __init__(self, base: BaseRetriever, client: PrivaroClient, role: str = "developer", **kw: Any):
        super().__init__(base=base, client=client, role=role, **kw)

    def _get_relevant_documents(self, query: str, *, run_manager: Any = None) -> List[Document]:
        return _protect_docs(self.client, self.base.invoke(query), self.role)
