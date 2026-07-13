-- Local-only semantic index.  Vectors are generated only by the configured
-- localhost Ollama embedding model; no cloud embedding provider is supported.
CREATE TABLE knowledge_chunks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    knowledge_item_id uuid NOT NULL REFERENCES knowledge_items(id) ON DELETE CASCADE,
    chunk_index integer NOT NULL CHECK (chunk_index >= 0),
    title text NOT NULL,
    content text NOT NULL,
    content_hash text NOT NULL,
    embedding vector(768),
    embedding_model text,
    indexed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (knowledge_item_id, chunk_index)
);

CREATE INDEX knowledge_chunks_search_idx
    ON knowledge_chunks USING gin (to_tsvector('english', title || ' ' || content));
CREATE INDEX knowledge_chunks_embedding_idx
    ON knowledge_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 25);
