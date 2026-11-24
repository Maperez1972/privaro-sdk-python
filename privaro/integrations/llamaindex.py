"""
LlamaIndex adapters (llama-index-core >= 0.10).  pip install "privaro[llamaindex]"

    from privaro.integrations.llamaindex import PrivaroNodePostprocessor, PrivaroTransform

    engine = index.as_query_engine(node_postprocessors=[PrivaroNodePostprocessor(client)])   # mask retrieved nodes
    pipeline = IngestionPipeline(transformations=[SentenceSplitter(), PrivaroTransform(client), embed_model])
"""
from __future__ import annotations

from typing import Any, List, Optional

from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import BaseNode, NodeWithScore, QueryBundle, TransformComponent

from privaro.client import PrivaroClient
from privaro.models import RetrievalChunk


def _protect(client: PrivaroClient, nodes: List[BaseNode], role: str) -> dict:
    res = client.protect_retrieval(
        [RetrievalChunk(id=str(i), text=n.get_content(), allowed_roles=n.metadata.get("allowed_roles")) for i, n in enumerate(nodes)],
        requester_role=role)
    return {c.id: c.protected_text for c in res.allowed_chunks}


class PrivaroNodePostprocessor(BaseNodePostprocessor):
    """Masks retrieved nodes; drops nodes the requester role may not see (metadata `allowed_roles`)."""

    client: Any = None
    role: str = "developer"

    def __init__(self, client: PrivaroClient, role: str = "developer", **kw: Any):
        super().__init__(client=client, role=role, **kw)

    @classmethod
    def class_name(cls) -> str:
        return "PrivaroNodePostprocessor"

    def _postprocess_nodes(self, nodes: List[NodeWithScore], query_bundle: Optional[QueryBundle] = None) -> List[NodeWithScore]:
        if not nodes:
            return nodes
        by_id = _protect(self.client, [n.node for n in nodes], self.role)
        out: List[NodeWithScore] = []
        for i, n in enumerate(nodes):
            if str(i) not in by_id:
                continue
            node = n.node.model_copy()
            node.set_content(by_id[str(i)])
            node.metadata = {**node.metadata, "privaro_masked": True}
            out.append(NodeWithScore(node=node, score=n.score))
        return out


class PrivaroTransform(TransformComponent):
    """IngestionPipeline step: masks node text before it is embedded/stored."""

    client: Any = None
    role: str = "developer"

    def __init__(self, client: PrivaroClient, role: str = "developer", **kw: Any):
        super().__init__(client=client, role=role, **kw)

    def __call__(self, nodes: List[BaseNode], **kwargs: Any) -> List[BaseNode]:
        out: List[BaseNode] = []
        for s in range(0, len(nodes), 200):
            batch = nodes[s:s + 200]
            by_id = _protect(self.client, batch, self.role)
            for i, n in enumerate(batch):
                if str(i) in by_id:
                    n.set_content(by_id[str(i)])
                    n.metadata = {**n.metadata, "privaro_masked": True}
                    out.append(n)
        return out
