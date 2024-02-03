import pandas as pd
import matplotlib.pyplot as plg
import json
from matplotlib import pyplot as plt


def read_data(file_name: str) -> pd.DataFrame:
    with open(file_name) as file:
        data = json.load(file)
        df = pd.DataFrame(data['events'])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df['signature'].value_counts()


df = read_data('data/events.json.txt')
plg.figure(figsize=(12, 9))
df.plot(kind='bar')
plt.title("Signatures count")
plt.xlabel("Signature name")
plt.ylabel("Count")
plt.xticks(rotation=-45, ha="left")
plt.tight_layout()
plt.show()
