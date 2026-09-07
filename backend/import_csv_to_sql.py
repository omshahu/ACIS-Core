import os
import sys
import time
import argparse
import pandas as pd

# Configure UTF-8 for console output on Windows
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from database import init_db, save_traffic_chunk, get_traffic_count, find_data_csv_path

def import_csv_to_sql(csv_path, chunksize=10000, sample_limit=None, replace=False):
    """
    Import data.csv into SQL database in chunks.
    """
    if not csv_path or not os.path.exists(csv_path):
        resolved = find_data_csv_path()
        if resolved and os.path.exists(resolved):
            csv_path = resolved
        else:
            print(f"[ERROR] CSV file not found at '{csv_path}'")
            return False

    file_size_mb = os.path.getsize(csv_path) / (1024 * 1024)
    print(f"[INFO] Selected CSV: {csv_path} ({file_size_mb:.2f} MB)")
    
    # Initialize DB (recreate table if replace=True)
    init_db(force_recreate=replace)

    initial_count = get_traffic_count()
    if initial_count > 0 and not replace and sample_limit is None:
        print(f"[INFO] Database already contains {initial_count:,} records.")
        print("       Use --replace to clear existing data or --sample to import additional records.")

    print(f"[START] Starting CSV to SQL import (chunk size: {chunksize:,} rows)...")
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
            print(f"       ↳ Chunk {i:03d}: Imported {total_imported:,} total rows ({rate:,.0f} rows/sec)")
            
    except Exception as e:
        print(f"[ERROR] Ingestion Error: {e}")
        return False

    elapsed = time.time() - start_time
    final_count = get_traffic_count()
    print(f"[OK] Ingestion Completed in {elapsed:.2f} seconds!")
    print(f"[STATS] Total database records in network_traffic: {final_count:,}")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ACIS-Core data.csv to SQL Database Importer")
    parser.add_argument('--csv', type=str, default=None, help='Path to data.csv file')
    parser.add_argument('--chunksize', type=int, default=10000, help='Chunk size for pandas streaming (default: 10000)')
    parser.add_argument('--sample', type=int, default=None, help='Import only a sample of N rows')
    parser.add_argument('--replace', action='store_true', help='Replace existing table data in SQL database')

    args = parser.parse_args()

    # Resolve CSV path
    csv_file = args.csv
    if not csv_file or not os.path.exists(csv_file):
        csv_file = find_data_csv_path()

    import_csv_to_sql(csv_file, chunksize=args.chunksize, sample_limit=args.sample, replace=args.replace)
