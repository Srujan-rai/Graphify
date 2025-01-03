from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlparse
import re
import json

app = Flask(__name__)
CORS(app) 


def extract_insert_into(sql_query):
    """Extract the target table for INSERT INTO."""
    match = re.search(r"INSERT INTO\s+([\w\.]+)", sql_query, re.IGNORECASE)
    return match.group(1) if match else None


def extract_columns(select_clause):
    """Extract column details from SELECT clause."""
    columns = []
    column_pattern = re.compile(
        r"(\w+\.\w+|\w+\s+AS\s+\w+|\w+\.\w+\s+AS\s+\w+|\w+|\*)", re.IGNORECASE
    )
    matches = column_pattern.findall(select_clause)
    for match in matches:
        column_info = {}
        if " AS " in match.upper():
            original, alias = match.upper().split(" AS ")
            column_info["original"] = original.strip()
            column_info["alias"] = alias.strip()
        else:
            column_info["original"] = match.strip()
            column_info["alias"] = None
        columns.append(column_info)
    return columns


def extract_tables_and_joins(from_clause):
    """Extract tables and join relationships."""
    tables = []
    joins = []

    # Extract tables
    table_pattern = re.compile(r"(FROM|JOIN)\s+([\w\.]+)\s*(?:AS\s+(\w+))?", re.IGNORECASE)
    for match in table_pattern.findall(from_clause):
        tables.append({
            "type": match[0].upper(),
            "table": match[1].strip(),
            "alias": match[2].strip() if match[2] else None
        })

    # Extract joins
    join_pattern = re.compile(r"(LEFT|RIGHT|INNER|FULL|CROSS)?\s*JOIN\s+([\w\.]+)\s+ON\s+(.+)", re.IGNORECASE)
    for match in join_pattern.findall(from_clause):
        joins.append({
            "type": match[0].upper() if match[0] else "JOIN",
            "table": match[1].strip(),
            "condition": match[2].strip()
        })

    return tables, joins


def extract_where_clause(sql_query):
    """Extract WHERE clause."""
    match = re.search(r"WHERE\s+(.+)", sql_query, re.IGNORECASE)
    return match.group(1).strip() if match else None


def parse_subqueries(sql_query):
    subqueries = []
    subquery_pattern = re.compile(r"\((SELECT.+?FROM.+?)\)", re.IGNORECASE | re.DOTALL)
    matches = subquery_pattern.findall(sql_query)

    for match in matches:
        subquery_content = match.strip("()")
        subqueries.append(parse_sql_query(subquery_content))  # Recursively parse subquery

    return subqueries


def extract_create_table(sql_query):
    """Extract details of CREATE TABLE statement."""
    result = {}
    create_table_pattern = re.search(
        r"CREATE\s+TABLE\s+([\w\.]+)\s*\((.+?)\)\s*(ENGINE=\w+)?", sql_query, re.IGNORECASE | re.DOTALL
    )
    if create_table_pattern:
        table_name = create_table_pattern.group(1).strip()
        columns_section = create_table_pattern.group(2).strip()
        engine = create_table_pattern.group(3).strip() if create_table_pattern.group(3) else None

        # Parse columns
        columns = []
        column_pattern = re.compile(r"(\w+)\s+([\w\(\)\s]+)(?:,|$)", re.IGNORECASE)
        for match in column_pattern.findall(columns_section):
            columns.append({
                "name": match[0].strip(),
                "definition": match[1].strip()
            })

        result["table_name"] = table_name
        result["columns"] = columns
        if engine:
            result["engine"] = engine
    return result


def parse_sql_query(sql_query):
    """Main function to parse SQL query into a comprehensive JSON structure."""
    result = {}

    # Normalize and format query
    formatted_query = sqlparse.format(sql_query, reindent=True, keyword_case="upper")

    # Check for CREATE TABLE
    if "CREATE TABLE" in formatted_query.upper():
        result["create_table"] = extract_create_table(formatted_query)
        return result

    # Existing logic for other queries
    # Parse INSERT INTO
    insert_into = extract_insert_into(formatted_query)
    if insert_into:
        result["insert_into"] = insert_into

    # Parse SELECT clause
    select_match = re.search(r"SELECT\s+DISTINCT\s+(.+?)\s+FROM", formatted_query, re.IGNORECASE | re.DOTALL)
    if not select_match:
        select_match = re.search(r"SELECT\s+(.+?)\s+FROM", formatted_query, re.IGNORECASE | re.DOTALL)
    if select_match:
        result["result_set"] = extract_columns(select_match.group(1))

    # Parse FROM clause
    from_match = re.search(r"FROM\s+(.+)", formatted_query, re.IGNORECASE | re.DOTALL)
    if from_match:
        from_clause = from_match.group(1).split("WHERE")[0].strip()
        tables, joins = extract_tables_and_joins(from_clause)
        if tables:
            result["tables"] = tables
        if joins:
            result["joins"] = joins

    # Parse WHERE clause
    where_clause = extract_where_clause(formatted_query)
    if where_clause:
        result["where"] = where_clause

    # Parse subqueries
    subqueries = parse_subqueries(formatted_query)
    if subqueries:
        result["subqueries"] = subqueries
    return result


@app.route('/parse-file', methods=['POST'])
def parse_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        sql_query = file.read().decode('utf-8')
        print(sql_query)
        parsed_result = parse_sql_query(sql_query)
        print(parsed_result)
        return jsonify(parsed_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
