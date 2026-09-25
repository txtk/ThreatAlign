from models.llm.qwen3 import qwen
from models.llm.xm import xm
from models.llm.ds import ds
from models.llm.glm import glm
from models.llm.silicon import scs

chat_mappinng = {
    "qwen": qwen,
    "xm": xm,
    "ds": ds,
    "glm": glm,
    "sc": scs,
}