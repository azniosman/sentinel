# Vector Store Directory

This directory contains the ChromaDB vector database for the RAG (Retrieval-Augmented Generation) pipeline.

## Directory Structure

```
vector_store/
└── chroma_db/          # ChromaDB persistent storage
    └── .gitkeep
```

## Purpose

The vector store enables semantic search over threat intelligence data using:

- **Embedding Model**: sentence-transformers (all-MiniLM-L6-v2)
- **Vector Database**: ChromaDB with persistent storage
- **Similarity Search**: Cosine similarity for document retrieval

## How RAG Works

```
User Query → Embedding → Vector Search → Top-K Documents → LLM Response
```

1. User asks a question about threats/CVEs/vulnerabilities
2. Query is converted to embedding vector
3. ChromaDB finds most similar documents
4. Top-K results provide context to LLM
5. LLM generates grounded response with sources

## Collection Details

- **Collection Name**: `threat_intelligence` (configurable)
- **Embedding Dimensions**: 384 (for all-MiniLM-L6-v2)
- **Distance Metric**: Cosine similarity
- **Persistence**: Files stored in `chroma_db/`

## Storage Requirements

| Data Volume | Approximate Size |
|-------------|------------------|
| 1,000 documents | ~10 MB |
| 10,000 documents | ~100 MB |
| 100,000 documents | ~1 GB |
| 1,000,000 documents | ~10 GB |

## Maintenance

### Reset Vector Store

⚠️ **WARNING**: This deletes all embeddings and requires re-ingestion.

```bash
# Docker deployment
docker-compose down
docker volume rm aisoc_aisoc_vector_store
docker-compose up -d

# Local deployment
rm -rf vector_store/chroma_db/*
# Restart backend to reinitialize
```

### Rebuild Embeddings

Trigger embedding refresh:

```bash
# Via API
curl -X POST http://localhost:8000/api/ingestion/update

# Or wait for scheduled update (every 12 hours)
```

## Performance Tuning

For large datasets:

1. Increase batch size in `RAGEngine.bulk_ingest_documents()`
2. Use GPU-accelerated embeddings (CUDA)
3. Consider FAISS index for faster search
4. Implement incremental updates

## Backup

```bash
# Backup vector store
tar -czf vector_store_backup_$(date +%Y%m%d).tar.gz vector_store/chroma_db/

# Restore
tar -xzf vector_store_backup_YYYYMMDD.tar.gz -C /
```
