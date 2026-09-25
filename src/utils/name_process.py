import ipaddress
import math
from collections import Counter
from uuid import uuid4

from utils.string_operate.regex import Regex

regex_remove_brackets = r"\(.*?\)"
regex_remove_word = r"apt|group|team"
regex_word_num = r"[^a-zA-Z0-9]"
semantic_pattern = r"[. _]"
num_char_pattern = r"[a-zA-Z]\d|\d[a-zA-Z]"


def num_char_rate(s):
    result = Regex.findall_num(num_char_pattern, s)
    if len(s) < 16:
        return True
    rate = result / len(s)
    if rate > 0.2:
        return False
    return True


def calculate_shannon_entropy(s):
    if not s:
        return 0
    entropy = 0
    length = len(s)
    counts = Counter(s)
    for count in counts.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    if entropy > 3.5:
        return False
    return True


def clean_name(name: str) -> str:
    """Clean and standardize a given name string."""
    name = name.lower().strip()
    name = Regex.remove(regex_remove_brackets, name)
    name = Regex.remove(regex_remove_word, name)
    name = Regex.remove(regex_word_num, name)
    return name.strip()


def get_name(entity: dict):
    if "name" in entity:
        name = entity["name"]
    elif "value" in entity:
        name = entity["value"]
    elif "hashes" in entity:
        name = str(entity["hashes"])
    elif "key" in entity:
        name = entity["key"]
    else:
        name = str(uuid4())
    return name


"""
description: Check whether an entity is semantic.
param {str} name
return {*}
"""


def semantic_judge(name: str):
    try:
        ipaddress.ip_address(name.strip())
        return False
    except ValueError:
        pass

    name = clean_name(name)
    if name.find("sha256") != -1 or name.find("md5") != -1 or name.find("sha1") != -1:
        return False

    if Regex.get_search_judge(name, semantic_pattern):
        return True
    return num_char_rate(name)
