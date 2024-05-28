import sys
from urllib.parse import urlparse

import pandas as pd
import psycopg2


def upload_classifications_to_db(database_connection_string, input_csv):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(input_csv)

    # Parse the label column into separate url_scheme, url_host, and url_path columns
    parsed_urls = df['label'].apply(urlparse)
    df['url_scheme'] = parsed_urls.apply(lambda x: x.scheme)
    df['url_host'] = parsed_urls.apply(lambda x: x.hostname)
    df['url_path'] = parsed_urls.apply(lambda x: x.path)

    # Drop the original label column
    df.drop(columns=['label'], inplace=True)

    # Connect to the PostgreSQL database
    print("Connecting to the database...")
    conn = psycopg2.connect(database_connection_string)
    cur = conn.cursor()

    # Clear the classifications table
    print("Clearing classifications table...")
    cur.execute("DELETE FROM classifications where true;")
    conn.commit()

    # Insert new values into the classifications table
    print("Uploading new classifications to the database...")
    for index, row in df.iterrows():
        cur.execute("""
            INSERT INTO classifications (url_scheme, url_host, url_path, class)
            VALUES (%s, %s, %s, %s) on conflict on constraint classifications_pk do update set class = %s;
        """, (row['url_scheme'], row['url_host'], row['url_path'], row['cluster_id'], row['cluster_id']))
    conn.commit()

    # Close the database connection
    cur.close()
    conn.close()
    print("Done.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python upload_classifications.py <database_connection_string> <input_csv>")
        sys.exit(1)

    db_conn_str = sys.argv[1]
    input_csv_path = sys.argv[2]
    upload_classifications_to_db(db_conn_str, input_csv_path)


if __name__ == "__main__":
    main()
