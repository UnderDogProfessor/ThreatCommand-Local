import unittest

from app.main import SEMANTIC_VECTOR_DIMENSION, knowledge_chunks_for_item, vector_literal


class LocalSemanticKnowledgeTests(unittest.TestCase):
    def test_chunking_preserves_title_and_overlaps_content(self):
        content = " ".join(f"word-{number}" for number in range(600))

        chunks = knowledge_chunks_for_item("Reviewed local note", content)

        self.assertEqual(len(chunks), 3)
        self.assertTrue(all(chunk.startswith("Reviewed local note\n\n") for chunk in chunks))
        self.assertIn("word-220", chunks[0])
        self.assertIn("word-220", chunks[1])

    def test_vector_literal_requires_the_local_pgvector_dimension(self):
        vector = [0.0] * SEMANTIC_VECTOR_DIMENSION

        self.assertTrue(vector_literal(vector).startswith("[0,"))
        with self.assertRaises(ValueError):
            vector_literal([0.0, 1.0])
