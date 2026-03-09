"""
RAG Threat Intelligence Engine
Local AI-Powered Security Operations Center

Retrieval-Augmented Generation for threat intelligence queries.
"""

import asyncio
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
import chromadb
from chromadb.config import Settings as ChromaSettings
from sentence_transformers import SentenceTransformer
import ollama

from config import settings
from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class RAGEngine:
    """RAG engine for threat intelligence retrieval and analysis."""
    
    def __init__(self):
        self.vector_store_path = Path(settings.VECTOR_STORE_PATH)
        self.collection_name = settings.VECTOR_STORE_COLLECTION
        self.embedding_model_name = settings.EMBEDDING_MODEL
        self.llm_model = settings.LLM_MODEL
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {self.embedding_model_name}")
        self.embedding_model = SentenceTransformer(self.embedding_model_name)
        self.embedding_dimension = self.embedding_model.get_sentence_embedding_dimension()
        
        # Initialize ChromaDB
        logger.info(f"Initializing ChromaDB at {self.vector_store_path}")
        self.chroma_client = chromadb.PersistentClient(
            path=str(self.vector_store_path),
            settings=ChromaSettings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )
        
        # Get or create collection
        self.collection = self.chroma_client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        
        logger.info(f"RAG engine initialized with collection: {self.collection_name}")
    
    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding vector for text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        embedding = self.embedding_model.encode(text, convert_to_numpy=True)
        return embedding.tolist()
    
    async def add_document(
        self,
        document_id: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Add a document to the vector store.
        
        Args:
            document_id: Unique document identifier
            text: Document text content
            metadata: Optional metadata
        """
        try:
            # Generate embedding
            embedding = self.generate_embedding(text)
            
            # Add to collection
            self.collection.add(
                ids=[document_id],
                embeddings=[embedding],
                documents=[text],
                metadatas=[metadata or {}],
            )
            
            logger.debug(f"Added document to vector store: {document_id}")
            
        except Exception as e:
            logger.error(f"Failed to add document: {str(e)}")
            raise
    
    async def add_threat_intelligence(self, threat_data: Dict[str, Any]):
        """
        Add threat intelligence record to vector store.
        
        Args:
            threat_data: Threat intelligence record
        """
        try:
            # Create searchable text from threat data
            text_parts = []
            
            if "cve_id" in threat_data:
                text_parts.append(f"CVE: {threat_data['cve_id']}")
                text_parts.append(f"Description: {threat_data.get('description', '')}")
                text_parts.append(f"CVSS Score: {threat_data.get('cvss_score', 'N/A')}")
                text_parts.append(f"Severity: {threat_data.get('severity', 'N/A')}")
                text_parts.append(f"Affected Products: {', '.join(threat_data.get('affected_products', []))}")
            
            elif "name" in threat_data and "threat_actor" in str(threat_data):
                text_parts.append(f"Threat Actor: {threat_data['name']}")
                text_parts.append(f"Description: {threat_data.get('description', '')}")
                text_parts.append(f"Type: {threat_data.get('type', 'N/A')}")
                text_parts.append(f"Motivation: {', '.join(threat_data.get('motivation', []))}")
            
            elif "title" in threat_data:
                text_parts.append(f"Title: {threat_data['title']}")
                text_parts.append(f"Description: {threat_data.get('description', '')}")
            
            text = " | ".join(text_parts)
            
            # Generate document ID
            doc_id = f"threat_{hashlib.md5(text.encode()).hexdigest()[:16]}"
            
            # Add metadata
            metadata = {
                "type": threat_data.get("type", "unknown"),
                "severity": threat_data.get("severity", "unknown"),
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            # Add to vector store
            await self.add_document(doc_id, text, metadata)
            
        except Exception as e:
            logger.error(f"Failed to add threat intelligence: {str(e)}")
    
    async def query(
        self,
        query: str,
        top_k: int = 5,
        include_sources: bool = True,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Query threat intelligence using RAG.
        
        Args:
            query: User query
            top_k: Number of results to retrieve
            include_sources: Include source documents in response
            context: Optional context for the query
            
        Returns:
            RAG response with answer and sources
        """
        query_start = datetime.utcnow()
        
        try:
            logger.info(f"Executing RAG query: {query}")
            
            # Log query received
            log_event(
                category=EventCategory.RAG_PIPELINE,
                event_type="RAG_QUERY_RECEIVED",
                module="rag_engine",
                message=f"RAG query received: {query[:100]}",
                severity=SeverityLevel.INFO,
                metadata={"query": query, "top_k": top_k},
            )

            # Generate query embedding
            query_embedding = self.generate_embedding(query)
            
            # Log embedding generated
            log_event(
                category=EventCategory.RAG_PIPELINE,
                event_type="EMBEDDING_GENERATED",
                module="rag_engine",
                message="Query embedding generated",
                severity=SeverityLevel.INFO,
                metadata={"query": query[:50], "model": self.embedding_model_name},
            )

            # Search vector store
            search_start = datetime.utcnow()
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                include=["documents", "metadatas", "distances"],
            )
            search_duration = (datetime.utcnow() - search_start).total_seconds() * 1000
            
            # Log vector search completed
            log_event(
                category=EventCategory.RAG_PIPELINE,
                event_type="VECTOR_SEARCH_COMPLETED",
                module="rag_engine",
                message=f"Vector search completed in {search_duration:.2f}ms",
                severity=SeverityLevel.INFO,
                metadata={
                    "query": query[:50],
                    "results_count": len(results.get("documents", [[]])[0]) if results.get("documents") else 0,
                    "latency_ms": search_duration,
                },
            )
            
            # Build context from retrieved documents
            context_docs = []
            sources = []
            
            if results.get("documents") and results["documents"][0]:
                for i, doc in enumerate(results["documents"][0]):
                    context_docs.append(doc)
                    
                    if include_sources and results.get("metadatas"):
                        metadata = results["metadatas"][0][i] if results["metadatas"][0] else {}
                        sources.append({
                            "document": doc[:200],  # First 200 chars
                            "metadata": metadata,
                            "relevance_score": 1 - results["distances"][0][i] if results.get("distances") else None,
                        })
            
            context_text = "\n\n".join(context_docs)
            
            # Build prompt for LLM
            system_prompt = """You are an AI cybersecurity analyst assistant. 
You provide accurate, concise answers about threat intelligence, vulnerabilities, 
and cybersecurity threats based on the provided context. 
If the context doesn't contain relevant information, say so clearly.
Always prioritize accuracy over speculation."""

            user_prompt = f"""Context from threat intelligence database:
{context_text}

User Question: {query}

Provide a comprehensive answer based on the context above. Include:
1. Direct answer to the question
2. Relevant CVE IDs, threat actors, or malware names if applicable
3. Severity and impact assessment
4. Mitigation recommendations if available

Answer:"""

            # Query local LLM via Ollama
            llm_response = await self._query_llm(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            
            # Build response
            response = {
                "query": query,
                "answer": llm_response.get("response", ""),
                "sources": sources if include_sources else [],
                "context_used": context_text if settings.DEBUG else None,
                "model": self.llm_model,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            total_duration = (datetime.utcnow() - query_start).total_seconds() * 1000
            
            # Log query completed
            log_event(
                category=EventCategory.RAG_PIPELINE,
                event_type="RAG_QUERY_COMPLETED",
                module="rag_engine",
                message="RAG query completed successfully",
                severity=SeverityLevel.INFO,
                metadata={
                    "query": query[:50],
                    "total_latency_ms": total_duration,
                    "sources_count": len(sources) if include_sources else 0,
                },
            )

            logger.info("RAG query completed")
            return response

        except Exception as e:
            logger.error(f"RAG query failed: {str(e)}")
            
            # Log query failed
            log_event(
                category=EventCategory.RAG_PIPELINE,
                event_type="RAG_QUERY_FAILED",
                module="rag_engine",
                message=f"RAG query failed: {str(e)}",
                severity=SeverityLevel.ERROR,
                metadata={"query": query[:50], "error": str(e)},
            )
            
            return {
                "query": query,
                "answer": f"Error processing query: {str(e)}",
                "sources": [],
                "timestamp": datetime.utcnow().isoformat(),
            }
    
    async def _query_llm(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        """
        Query local LLM via Ollama.
        
        Args:
            system_prompt: System instruction
            user_prompt: User message
            
        Returns:
            LLM response
        """
        try:
            loop = asyncio.get_event_loop()
            
            def sync_query():
                response = ollama.chat(
                    model=self.llm_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    options={
                        "temperature": settings.LLM_TEMPERATURE,
                        "num_predict": settings.LLM_MAX_TOKENS,
                    },
                )
                return response
            
            response = await loop.run_in_executor(None, sync_query)
            
            return {
                "response": response["message"]["content"],
                "model": self.llm_model,
            }
            
        except Exception as e:
            logger.error(f"LLM query failed: {str(e)}")
            return {
                "response": f"LLM unavailable: {str(e)}",
                "model": self.llm_model,
            }
    
    async def bulk_ingest_documents(
        self,
        documents: List[Dict[str, Any]],
        batch_size: int = 100,
    ):
        """
        Bulk ingest documents into vector store.
        
        Args:
            documents: List of documents with 'id', 'text', and 'metadata'
            batch_size: Number of documents to process at once
        """
        logger.info(f"Bulk ingesting {len(documents)} documents")
        
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            
            embeddings = []
            ids = []
            texts = []
            metadatas = []
            
            for doc in batch:
                try:
                    text = doc.get("text", "")
                    if not text:
                        continue
                    
                    embedding = self.generate_embedding(text)
                    
                    embeddings.append(embedding)
                    ids.append(doc.get("id", f"doc_{len(ids)}"))
                    texts.append(text)
                    metadatas.append(doc.get("metadata", {}))
                    
                except Exception as e:
                    logger.error(f"Failed to process document: {str(e)}")
            
            if embeddings:
                self.collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=texts,
                    metadatas=metadatas,
                )
                
                logger.info(f"Ingested batch {i // batch_size + 1}")
            
            # Small delay to avoid overwhelming the system
            await asyncio.sleep(0.1)
        
        logger.info("Bulk ingestion completed")
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """
        Get vector store collection statistics.
        
        Returns:
            Collection statistics
        """
        try:
            count = self.collection.count()
            
            return {
                "collection_name": self.collection_name,
                "document_count": count,
                "embedding_model": self.embedding_model_name,
                "embedding_dimension": self.embedding_dimension,
                "llm_model": self.llm_model,
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {str(e)}")
            return {"error": str(e)}
