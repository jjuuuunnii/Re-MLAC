import threading
import requests
import pandas as pd
import os
import pymysql
from dbutils.pooled_db import PooledDB
import time
from datetime import datetime
import logging
from dotenv import load_dotenv
from packet_info_schema import PacketInfoSchema
from label_util import LabelUtil
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
URL = os.getenv('POST_URL')

packet_info_schema = PacketInfoSchema()
label_util = LabelUtil()

pool = PooledDB(
    creator=pymysql,
    maxconnections=50,
    mincached=10,
    maxcached=20,
    maxusage=None,
    blocking=True,
    host=os.getenv('DB_HOST'),
    port=int(os.getenv('DB_PORT')),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME'),
    charset='utf8mb4'
)

log_queue = Queue()

def log_worker():
    while True:
        message = log_queue.get()
        if message is None:
            break
        logging.info(message)
        log_queue.task_done()

def periodic_log(datas, processed_indices):
    while True:
        total_remaining = sum(len(data) - len(processed_indices[fn]) for fn, data in datas)
        log_queue.put(f"{total_remaining} data remaining.")
        time.sleep(5)  # Log every 5 seconds

def send_request(data, filename, processed_indices):
    db_connection = pool.connection()
    category_labels = label_util.get_category_label()
    user_labels = label_util.get_user_label()
    script_labels = label_util.get_script_label()
    restricted_script_labels = label_util.get_restricted_script_label()

    indices = list(data.index)

    try:
        while len(processed_indices[filename]) < len(data):
            current_index = random.choice(indices)
            if current_index in processed_indices[filename]:
                continue

            current_row = data.loc[current_index]
            processed_indices[filename].add(current_index)

            ip = current_row['srcip']
            port = str(current_row['sport'])
            input_id = current_row['index']
            category_label_index = current_row['category_label']
            label = category_labels[category_label_index]

            timestamp = datetime.now().isoformat()
            body = {'timestamp': timestamp}

            try:
                with db_connection.cursor() as cursor:
                    if label in user_labels:
                        cursor.execute("SELECT username, password FROM dummy_users WHERE type = %s ORDER BY RAND() LIMIT 1", (label,))
                        result = cursor.fetchone()
                        if result:
                            body.update({
                                'username': result[0],
                                'password': result[1]
                            })
                    elif label in script_labels:
                        if label in restricted_script_labels:
                            cursor.execute("SELECT content FROM dummy_scripts WHERE type != 'WEB_ATTACK_SQL_INJECTION' ORDER BY RAND() LIMIT 1")
                        else:
                            cursor.execute("SELECT content FROM dummy_scripts WHERE type = %s ORDER BY RAND() LIMIT 1", (label,))
                        result = cursor.fetchone()
                        if result:
                            body.update({
                                'script': result[0]
                            })
            except Exception as e:
                log_queue.put(f'Database query error for {filename}: {str(e)}')
                continue

            packet_info = packet_info_schema.from_dataframe(current_row)

            request_data = {
                'ip': ip,
                'port': port,
                'input_id': int(input_id),
                'body': body,
                'packet_info': packet_info
            }
            try:
                response = requests.post(URL, json=request_data)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                log_queue.put(f'HTTP request error for {filename}: {str(e)}')

            time.sleep(0.001)  # Small delay to prevent overloading the server

    except Exception as e:
        log_queue.put(f'Error in send_request for {filename}: {str(e)}')
    finally:
        db_connection.close()

def load_data():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(script_dir, '..')
    filenames = [os.path.join(project_root, f"data/origin/re_cm_unsw_nb15_{i}.csv") for i in range(1, 31)]

    datas = []
    processed_indices = {}

    for fn in filenames:
        try:
            data = pd.read_csv(fn)
            datas.append((fn, data))
            logging.info(f'Successfully Loaded {fn}')
            processed_indices[fn] = set()
        except Exception as e:
            log_queue.put(f'{fn} could not be loaded: {str(e)}')

    return datas, processed_indices

def send_multiple_requests(datas, processed_indices):
    logging.info("Starting send_multiple_requests")
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = [executor.submit(send_request, data, filename, processed_indices) for filename, data in datas]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f'Exception in send_multiple_requests: {str(e)}')

    logging.info("Completed send_multiple_requests")

if __name__ == "__main__":
    datas, processed_indices = load_data()

    log_thread = threading.Thread(target=log_worker, daemon=True)
    log_thread.start()

    periodic_log_thread = threading.Thread(target=periodic_log, args=(datas, processed_indices), daemon=True)
    periodic_log_thread.start()

    send_multiple_requests(datas, processed_indices)

    log_queue.put(None)
    log_thread.join()
    periodic_log_thread.join()
