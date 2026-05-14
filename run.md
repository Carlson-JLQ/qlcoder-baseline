
/home/byteide/miniconda3/envs/qlcoder/bin/chroma run --path data/chroma_db

/home/byteide/miniconda3/envs/qlcoder/bin/python src/ql_agent.py --cve-id CVE-2025-48734 --output-dir src/output --model gpt-5.5-2026-04-24 --agent codex


/home/byteide/miniconda3/envs/qlcoder/bin/python vulnsynth/vulnsynth.py --cve-id CVE-2025-49009 --agent codex --model gpt-5.5-2026-04-24


/home/byteide/miniconda3/envs/qlcoder/bin/python vulnsynth/vulnsynth.py --cve-id CVE-2025-49009 --agent coco --model gpt-5.4
/home/byteide/miniconda3/envs/qlcoder/bin/python vulnsynth/vulnsynth.py --cve-id CVE-2025-49656 --agent coco --model gpt-5.4