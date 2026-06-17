"""A pgvector-backed RAG knowledge base for the support assistant.

Demonstrates:
- Vector store / RAG detection (pgvector + a LangChain retrieval pipeline)
- Risk indicators: retrieved content reaches the model (RAG data flow),
  application data embedded for retrieval, and external ingestion (the RAG
  poisoning surface)
"""
from __future__ import annotations

from langchain_community.document_loaders import WebBaseLoader
from langchain_openai import OpenAIEmbeddings
from langchain_postgres.vectorstores import PGVector

# Embeddings model used to index and query the knowledge base.
embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

# pgvector-backed store. Lives in the same Postgres instance as the app data.
knowledge_store = PGVector(
    embeddings=embeddings,
    collection_name="support_kb",
    connection="postgresql+psycopg://localhost:5432/app",
)


def ingest_help_center(url: str = "https://help.example.com/articles") -> None:
    """Pull help-center articles from an external URL and index them as-is.

    There is no review step between fetch and index (RAG poisoning surface).
    """
    docs = WebBaseLoader(url).load()
    knowledge_store.add_documents(docs)


# Retriever handed to the support agent; retrieved content reaches the model.
retriever = knowledge_store.as_retriever(search_kwargs={"k": 4})


def search_knowledge(query: str) -> str:
    matches = retriever.invoke(query)
    return "\n\n".join(d.page_content for d in matches)
