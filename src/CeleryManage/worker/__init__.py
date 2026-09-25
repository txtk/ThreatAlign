from utils import WORKER_MAP as utils_worker_map
from data_process import WORKER_MAP as data_process_worker_map
from threatalign import WORKER_MAP as alignment_worker_map

WORKER_MAP = dict()
WORKER_MAP.update(data_process_worker_map)
WORKER_MAP.update(utils_worker_map)
WORKER_MAP.update(alignment_worker_map)
NAME_MAP = dict()
