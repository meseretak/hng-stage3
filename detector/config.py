import os
import yaml


def load_config(path="/app/config.yaml"):
    with open(path) as f:
        raw = yaml.safe_load(f)

    # Expand env vars in string values
    def expand(val):
        if isinstance(val, str):
            return os.path.expandvars(val)
        return val

    return {k: expand(v) for k, v in raw.items()}


CFG = load_config()
