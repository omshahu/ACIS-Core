import os
import sys
import time
import argparse
import pandas as pd
from database import init_db, save_traffic_chunk, get_traffic_count

def import_csv_to_sql(csv_path, chunksize=50000, sample_limit=None, replace=False):
    """
    Import data.csv into SQL database in chunks.
    """
    if not os.path.exists(csv_path):
        print(f"❌ Error: CSV file not found at '{csv_path}'")
        return False

    file_size_mb = os.path.getsize(csv_path) / (1024 * 1024)
    print(f"📂 Selected CSV: {csv_path} ({file_size_mb:.2f} MB)")
    
    # Initialize DB
    init_db()

    initial_count = get_traffic_count()
    if initial_count > 0 and not replace and sample_limit is None:
        print(f"ℹ️ Database already contains {initial_count:,} records.")
        print("   Use --replace to clear existing data or --sample to import additional records.")

    print(f"🚀 Starting CSV to SQL import (chunk size: {chunksize:,} rows)...")
    start_time = time.time()
    
    total_imported = 0
    first_chunk = True

    try:
        chunk_iter = pd.read_csv(csv_path, chunksize=chunksize, low_memory=False)
        for i, chunk in enumerate(chunk_iter, 1):
            if sample_limit and total_imported >= sample_limit:
                break
                
            if sample_limit and (total_imported + len(chunk)) > sample_limit:
                chunk = chunk.iloc[:sample_limit - total_imported]

            if_exists_mode = 'replace' if (first_chunk and replace) else 'append'
            save_traffic_chunk(chunk, if_exists=if_exists_mode)
            
            total_imported += len(chunk)
            first_chunk = False
            
            elapsed = time.time() - start_time
            rate = total_imported / elapsed if elapsed > 0 else 0
            print(f"   ↳ Chunk {i:03d}: Imported {total_imported:,} total rows ({rate:,.0f} rows/sec)")
            
    except Exception as e:
        print(f"❌ Ingestion Error: {e}")
        return False

    elapsed = time.time() - start_time
    final_count = get_traffic_count()
    print(f"✅ Ingestion Completed in {elapsed:.2f} seconds!")
    print(f"📊 Total database records in network_traffic: {final_count:,}")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ACIS-Core data.csv to SQL Database Importer")
    parser.add_argument('--csv', type=str, default='../data.csv', help='Path to data.csv file')
    parser.add_argument('--chunksize', type=int, default=50000, help='Chunk size for pandas streaming (default: 50000)')
    parser.add_argument('--sample', type=int, default=None, help='Import only a sample of N rows')
    parser.add_argument('--replace', action='store_true', help='Replace existing table data in SQL database')

    args = parser.parse_args()

    # Fallback path check
    csv_file = args.csv
    if not os.path.exists(csv_file):
        if os.path.exists('data.csv'):
            csv_file = 'data.csv'
        elif os.path.exists('../data.csv'):
            csv_file = '../data.csv'

    import_csv_to_sql(csv_file, chunksize=args.chunksize, sample_limit=args.sample, replace=args.replace)
