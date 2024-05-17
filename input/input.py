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

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
URL = os.getenv('POST_URL')

packet_info_schema = PacketInfoSchema()
label_util = LabelUtil()
processed_indices = {}
log_lock = threading.Lock()  # 로그 출력을 위한 락 객체

pool = PooledDB(
    creator=pymysql,
    maxconnections=20,
    mincached=5,
    maxcached=15,
    maxusage=None,
    blocking=True,
    host=os.getenv('DB_HOST'),
    port=int(os.getenv('DB_PORT')),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME'),
    charset='utf8mb4'
)

def send_request(data, filename):
    db_connection = pool.connection()
    category_labels = label_util.get_category_label()
    user_labels = label_util.get_user_label()
    script_labels = label_util.get_script_label()
    restricted_script_labels = label_util.get_restricted_script_label()

    indices = list(data.index)
    if filename not in processed_indices:
        processed_indices[filename] = set()

    while len(processed_indices[filename]) < len(data):
        try:
            remaining_indices = list(set(indices) - processed_indices[filename])
            current_index = random.choice(remaining_indices)
            current_row = data.loc[current_index]
            processed_indices[filename].add(current_index)

            ip = current_row['srcip']
            port = str(current_row['sport'])
            input_id = current_row['index']
            category_label_index = current_row['category_label']

            if 0 <= category_label_index < len(category_labels):
                label = category_labels[category_label_index]
            else:
                logging.error(f'Invalid category_label index: {category_label_index}')
                continue

            timestamp = datetime.now().isoformat()
            body = {'timestamp': timestamp}

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
                else:
                    body.update({})

            packet_info = packet_info_schema.from_dataframe(current_row)

            request_data = {
                'ip': ip,
                'port': port,
                'input_id': int(input_id),
                'body': body,
                'packet_info': packet_info
            }
            response = requests.post(URL, json=request_data)
            time.sleep(0.001)  # 0.001초 지연

        except Exception as e:
            logging.error(f'Error in send_request for {filename}: {str(e)}')
            time.sleep(0.1)

    logging.info(f"All rows have been processed for {filename}")
    db_connection.close()

def load_data():
    filenames = [f"../data/origin/re_cm_unsw_nb15_{i}.csv" for i in range(1, 31)]
    datas = []
    for fn in filenames:
        try:
            data = pd.read_csv(fn)
            datas.append((fn, data))
            logging.info(f'Successfully loaded {fn}')
            processed_indices[fn] = set()  # 각 파일에 대한 processed_indices 초기화
        except Exception as e:
            logging.error(f'{fn} could not be loaded: {str(e)}')
            continue  # 읽기 실패 시 해당 파일을 건너뜁니다.
    return datas

def send_multiple_requests(datas):
    logging.info("Starting send_multiple_requests")
    threads = []

    for filename, data in datas:
        thread = threading.Thread(target=send_request, args=(data, filename))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    logging.info("Completed send_multiple_requests")

def log_remaining_data(datas):
    while any(len(processed_indices[fn]) < len(data) for fn, data in datas):
        with log_lock:
            total_remaining = sum(len(data) - len(processed_indices[fn]) for fn, data in datas)
            logging.info(f"{total_remaining} data remaining.")
        time.sleep(10)  # 10초마다 로그 출력

if __name__ == "__main__":
    datas = load_data()

    logging_thread = threading.Thread(target=log_remaining_data, args=(datas,))
    logging_thread.start()

    send_multiple_requests(datas)

    logging_thread.join()
