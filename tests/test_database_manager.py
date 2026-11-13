import sqlite3
import tempfile
import unittest
from pathlib import Path

from networkradar_modules.database.manager import DatabaseManager, NestedWriteError


class DatabaseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.manager = DatabaseManager(self.db_path, batch_interval=0.005)

    def tearDown(self):
        self.manager.stop(timeout=5)
        self.temp_dir.cleanup()

    def test_serialized_write_and_read(self):
        self.manager.start()
        self.manager.write(
            lambda conn: conn.execute(
                "CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)"
            )
        )
        self.manager.write(
            lambda conn: conn.execute(
                "INSERT INTO sample(value) VALUES (?)", ("hello",)
            )
        )
        with self.manager.read() as conn:
            row = conn.execute("SELECT value FROM sample WHERE id=1").fetchone()
        self.assertEqual(row["value"], "hello")

    def test_failed_write_rolls_back_and_writer_remains_usable(self):
        self.manager.start()
        self.manager.write(
            lambda conn: conn.execute(
                "CREATE TABLE sample (value TEXT UNIQUE)"
            )
        )
        self.manager.write(
            lambda conn: conn.execute(
                "INSERT INTO sample(value) VALUES ('first')"
            )
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.manager.write(
                lambda conn: conn.execute(
                    "INSERT INTO sample(value) VALUES ('first')"
                )
            )
        self.manager.write(
            lambda conn: conn.execute(
                "INSERT INTO sample(value) VALUES ('second')"
            )
        )
        with self.manager.read() as conn:
            values = [row["value"] for row in conn.execute(
                "SELECT value FROM sample ORDER BY value"
            )]
        self.assertEqual(values, ["first", "second"])

    def test_nested_write_is_rejected(self):
        self.manager.start()

        def outer(conn):
            self.manager.write(lambda nested: None)

        with self.assertRaises(NestedWriteError):
            self.manager.write(outer)

    def test_stop_flushes_queued_writes(self):
        self.manager.start()
        self.manager.write(
            lambda conn: conn.execute(
                "CREATE TABLE sample (value INTEGER)"
            )
        )
        self.manager.submit_async(
            lambda conn: conn.execute("INSERT INTO sample(value) VALUES (7)")
        )
        self.assertTrue(self.manager.flush(timeout=5))
        self.assertTrue(self.manager.stop(timeout=5))
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM sample"
            ).fetchone()[0], 7)


if __name__ == "__main__":
    unittest.main()
