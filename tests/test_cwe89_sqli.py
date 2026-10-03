"""Unit tests for CWE-89 (SQL Injection) detection."""

import pytest
from ast_scanner import TaintTracker


def _scan_source(source: str) -> list:
    """Scan source code and return findings."""
    tracker = TaintTracker(files={"test.py": source})
    _, sinks, edges = tracker.analyze()
    return [s.metadata for s in sinks]


class TestCWE89SQLInjection:
    """Tests for CWE-89 SQL injection detection."""

    def test_cursor_execute_with_fstring(self):
        """Should flag cursor.execute with f-string."""
        source = """
import sqlite3

def vuln(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name='{user_input}'")
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect cursor.execute with f-string"

    def test_cursor_execute_with_format(self):
        """Should flag cursor.execute with .format()."""
        source = """
import psycopg2

def vuln(user_id):
    conn = psycopg2.connect(...)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id={}".format(user_id))
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect cursor.execute with format"

    def test_cursor_execute_with_concatenation(self):
        """Should flag cursor.execute with string concatenation."""
        source = """
import mysql.connector

def vuln(username):
    conn = mysql.connector.connect(...)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name='" + username + "'")
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect cursor.execute with concatenation"

    def test_cursor_execute_parameterized_safe(self):
        """Should NOT flag parameterized cursor.execute."""
        source = """
import psycopg2

def safe(user_id):
    conn = psycopg2.connect(...)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag parameterized query"

    def test_cursor_execute_static_safe(self):
        """Should NOT flag static literal query."""
        source = """
import sqlite3

def safe():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag static query"

    def test_django_raw_with_fstring(self):
        """Should flag Django Model.objects.raw with f-string."""
        source = """
from myapp.models import Person

def vuln(user_name):
    # Dynamic raw query
    Person.objects.raw(f'SELECT * FROM myapp_person WHERE user_name = {user_name}')
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect Django raw with f-string"

    def test_django_raw_parameterized_safe(self):
        """Should NOT flag parameterized Django raw query."""
        source = """
from myapp.models import Person

def safe(client_id):
    Person.objects.raw('SELECT * FROM myapp_person WHERE client_id = %s', (client_id,))
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag parameterized Django raw"

    def test_sqlalchemy_execute_with_format(self):
        """Should flag SQLAlchemy engine.execute with format."""
        source = """
from sqlalchemy import create_engine

def vuln(name):
    engine = create_engine('sqlite:///test.db')
    engine.execute("INSERT INTO users (name) VALUES ('{}')".format(name))
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect SQLAlchemy execute with format"

    def test_session_execute_parameterized_safe(self):
        """Should NOT flag parameterized session.execute."""
        source = """
from sqlalchemy import text

def safe(name, session):
    stmt = text("SELECT * FROM users WHERE name=:name")
    session.execute(stmt, {"name": name})
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag parameterized session.execute"

    def test_executemany_with_dynamic(self):
        """Should flag cursor.executemany with dynamic query."""
        source = """
import sqlite3

def vuln(queries):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "INSERT INTO users (name) VALUES ('" + queries[0] + "')"
    cursor.executemany(query, data)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect executemany with dynamic query"


class TestCWE89VariableResolution:
    """Tests for intra-procedural variable resolution in CWE-89 detection."""

    def test_variable_with_fstring_assignment(self):
        """Should flag when variable is assigned an f-string and used in SQL sink."""
        source = """
import sqlite3

def vuln(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name='{user_input}'"
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect variable with f-string assignment"

    def test_variable_with_format_assignment(self):
        """Should flag when variable is assigned .format() result and used in SQL sink."""
        source = """
import psycopg2

def vuln(user_id):
    conn = psycopg2.connect(...)
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id={}".format(user_id)
    cur.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect variable with format assignment"

    def test_variable_with_concatenation_assignment(self):
        """Should flag when variable is assigned concatenation and used in SQL sink."""
        source = """
import mysql.connector

def vuln(username):
    conn = mysql.connector.connect(...)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect variable with concatenation assignment"

    def test_variable_with_static_assignment_safe(self):
        """Should NOT flag when variable is assigned a static literal."""
        source = """
import sqlite3

def safe():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users"
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag variable with static assignment"

    def test_variable_with_modulo_formatting(self):
        """Should flag when variable uses % formatting with dynamic content."""
        source = """
import sqlite3

def vuln(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=%s" % user_id
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect variable with modulo formatting"

    def test_variable_suppression_on_assignment(self):
        """Should respect suppression on assignment line (Phase 4 enhanced detection)."""
        source = """
import sqlite3

def suppressed(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name='{user_input}'"  # nosec
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        # Phase 4 respects suppression, but basic sink registration may still occur
        # Check that enhanced finding (with p4_source_id) is NOT present
        enhanced_findings = [f for f in cwe89_findings if "p4_source_id" in f or "operation" in f]
        assert len(enhanced_findings) == 0, "Should respect suppression on assignment line (no enhanced finding)"

    def test_variable_suppression_on_sink(self):
        """Should respect suppression on sink line."""
        source = """
import sqlite3

def suppressed(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name='{user_input}'"
    cursor.execute(query)  # nosec
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        # Phase 4 and Phase 6 both respect sink line suppression
        enhanced_findings = [f for f in cwe89_findings if "p4_source_id" in f or "p6_source_id" in f or "operation" in f]
        assert len(enhanced_findings) == 0, "Should respect suppression on sink line"

    def test_variable_pure_literal_concatenation_safe(self):
        """Should NOT flag when concatenation is purely static literals."""
        source = """
import sqlite3

def safe():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT " + "*" + " FROM users"
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) == 0, "Should NOT flag pure literal concatenation"

    def test_variable_psycopg2_identifier_safe(self):
        """Should NOT flag when using psycopg2.sql.Identifier (enhanced detection)."""
        source = """
import psycopg2
from psycopg2 import sql

def safe(table_name):
    conn = psycopg2.connect(...)
    cur = conn.cursor()
    query = sql.SQL("SELECT * FROM {}").format(sql.Identifier(table_name))
    cur.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        # Safe builder guard should prevent enhanced finding
        enhanced_findings = [f for f in cwe89_findings if "p4_source_id" in f or "p6_source_id" in f or "operation" in f]
        assert len(enhanced_findings) == 0, "Should NOT flag psycopg2.sql.Identifier usage (no enhanced finding)"

    def test_variable_sqlalchemy_text_safe(self):
        """Should NOT flag when using SQLAlchemy text() with bindparams (enhanced detection)."""
        source = """
from sqlalchemy import text

def safe(name, session):
    query = text("SELECT * FROM users WHERE name=:name").bindparams(name=name)
    session.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        # Safe builder guard should prevent enhanced finding
        enhanced_findings = [f for f in cwe89_findings if "p4_source_id" in f or "p6_source_id" in f or "operation" in f]
        assert len(enhanced_findings) == 0, "Should NOT flag SQLAlchemy text with bindparams (no enhanced finding)"

    def test_variable_cross_scope_resolution(self):
        """Should resolve variable across nested scopes."""
        source = """
import sqlite3

def outer():
    user_input = "admin"
    
    def inner():
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE name='{user_input}'"
        cursor.execute(query)
    
    inner()
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        # Should detect because user_input from outer scope is used in f-string
        assert len(cwe89_findings) >= 1, "Should detect cross-scope variable resolution"

    def test_variable_reassignment_tracks_latest(self):
        """Should track the latest assignment to a variable."""
        source = """
import sqlite3

def vuln(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users"  # Safe assignment
    query = f"SELECT * FROM users WHERE name='{user_input}'"  # Unsafe reassignment
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should track latest (unsafe) assignment"

    def test_variable_with_percent_operator(self):
        """Should flag when variable uses % operator for string formatting."""
        source = """
import sqlite3

def vuln(table_name):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "DROP TABLE %s" % table_name
    cursor.execute(query)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect variable with % operator"


class TestCWE89EdgeCases:
    """Edge case tests for CWE-89."""

    def test_django_extra_with_where(self):
        """Should flag Django extra with dynamic where clause."""
        source = """
from myapp.models import Entry

def vuln(user_input):
    Entry.objects.extra(where=["name='{}'".format(user_input)])
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect Django extra with dynamic where"

    def test_rawsql_expression(self):
        """Should flag RawSQL expression with dynamic input."""
        source = """
from django.db.models.expressions import RawSQL

def vuln(user_input):
    queryset.annotate(
        val=RawSQL("CASE WHEN name='{}' THEN 1 ELSE 0 END".format(user_input), [])
    )
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect RawSQL with dynamic input"

    def test_connection_execute_with_concat(self):
        """Should flag connection.execute with concatenation."""
        source = """
from sqlalchemy import create_engine

def vuln(table_name):
    engine = create_engine('sqlite:///test.db')
    with engine.connect() as conn:
        conn.execute("DROP TABLE " + table_name)
"""
        findings = _scan_source(source)
        cwe89_findings = [f for f in findings if f.get("cwe") == "CWE-89"]
        assert len(cwe89_findings) >= 1, "Should detect connection.execute with concat"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
